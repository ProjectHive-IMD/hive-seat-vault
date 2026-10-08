// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @notice IMD's ERC-8004 agent-registration adapter (the adapter checks collection.ownerOf(tokenId) == caller).
/// @dev    First arg is TokenStandard (an enum = ABI uint8), matching the live Adapter8004 selector
///         0xb68ca002. It was uint256 (selector 0x1f354cc5) before the 2026-10-08 audit, so every call reverted.
interface IImdAgentAdapter {
    function register(uint8 standard, address collection, uint256 tokenId, string calldata agentURI)
        external
        returns (uint256 agentId);
    /// @dev selector 0x0af28bd3; adapter gates it on collection.ownerOf(tokenId) == caller (= this vault).
    function setAgentURI(uint256 agentId, string calldata agentURI) external;
}

/// @notice ENS reverse registrar — lets this contract set its own primary ENS name (cosmetic only).
interface IEnsReverseRegistrar {
    function setName(string calldata name) external returns (bytes32);
}

/**
 * @title  HiveSeatVault
 * @notice Custody vault for Project Hive's identity.md seat NFTs. Seats keep running and earning, but can
 *         only LEAVE through the owner — which is a 48h TimelockController — so no seat can be moved or sold
 *         without a public, on-chain delay. Deposits are open; earnings sweep freely to a fixed sink; a
 *         scoped operator hot-key can pair/run seats but can NEVER move them.
 *
 *         The pairing layer (authorizeWorker / revokeWorkerAuthorization / registerAgent / isValidSignature /
 *         workerAuthorizationDigest) is lifted verbatim from the audited IMDSeatStrategy
 *         (impl 0x428a7afa2edfb06fc75fb64320ef3a77d9e15c55) so IMD accepts this contract as a seat's signer.
 *
 *  INVARIANTS (auditors verify — see HIVE-SEAT-VAULT-SPEC.md §7/§8):
 *    I1. A seat leaves ONLY via withdrawSeat(), which is onlyOwner (= the Timelock). rescueERC721 reverts on
 *        the seat collection, so it is not a second exit.
 *    I2. The vault never approves a seat to anyone (no approve / setApprovalForAll is ever called).
 *    I3. seatOperator's only powers are authorizeWorker / revokeWorkerAuthorization / registerAgent
 *        (once per seat — no duplicate spam; the owner can force a re-register or correct a URI).
 *    I4. isValidSignature returns VALID only for digests inserted by authorizeWorker — i.e. well-formed
 *        WorkerAuthorizations whose wallet == this and whose token the vault owns. Never an arbitrary hash.
 *        (This is the anti-rug crux: a hot key must never make the vault "sign" a sale / Seaport order.)
 *    I5. sweepEarnings can never move a seat: ERC-20 interface only, reverts on the seat collection,
 *        destination is the fixed rewardSink. sweepETH likewise pays only the fixed rewardSink.
 *    I6. setSeatOperator / setRewardSink / withdrawSeat / setEnsName / rescueERC721 are all onlyOwner
 *        (delayed + public). renounceOwnership() is disabled, so the Timelock can never be dropped.
 *    I7. Non-upgradeable: no proxy, no delegatecall, no selfdestruct. The rules cannot change silently.
 *    I8. A pairing is VALID only while fresh: it expires on-chain at expiresAt, dies when the operator is
 *        CHANGED (authEpoch — any change retires EVERY live pairing, a clean slate, not only the old key's)
 *        and dies when its seat is withdrawn (custodyEpoch) — a re-deposit does NOT re-arm it. A leaked
 *        operator key loses its pairings on rotation; note expiresAt is operator-chosen, so the 48h rotation
 *        (not a pairing's own expiry) is the real neutraliser. (added post-audit 2026-10-08)
 */
contract HiveSeatVault is Ownable2Step, ReentrancyGuard, IERC721Receiver {
    using SafeERC20 for IERC20;

    /* ------------------------------------------------------------------ *
     *  EIP-712 — identical to IMD's WorkerAuthorization domain (version 2) *
     * ------------------------------------------------------------------ */
    bytes32 private constant WORKER_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant WORKER_DOMAIN_NAME_HASH = keccak256("IdentityMD Worker");
    bytes32 private constant WORKER_DOMAIN_VERSION_HASH = keccak256("2");
    bytes32 private constant WORKER_AUTHORIZATION_TYPEHASH = keccak256(
        "WorkerAuthorization(bytes32 deviceKey,address wallet,uint256 tokenId,bytes32 nonce,uint64 expiresAt,string relayOrigin)"
    );
    bytes4 private constant ERC1271_VALID = 0x1626ba7e;
    bytes4 private constant ERC1271_INVALID = 0xffffffff;

    struct WorkerAuthorization {
        bytes32 deviceKey;
        address wallet;
        uint256 tokenId;
        bytes32 nonce;
        uint64 expiresAt;
        string relayOrigin;
    }

    /* ------------------------------------------------------------------ *
     *  Immutables                                                         *
     * ------------------------------------------------------------------ */
    IERC721 public immutable seatCollection; // identity.md NFT
    IImdAgentAdapter public immutable agentAdapter; // ERC-8004 registration
    IEnsReverseRegistrar public immutable ensReverseRegistrar; // may be address(0) off-mainnet

    /* ------------------------------------------------------------------ *
     *  Config (owner = Timelock → every change is delayed + public)       *
     * ------------------------------------------------------------------ */
    address public seatOperator; // hot key: pair/run only, cannot move seats
    address public rewardSink; // where swept earnings go

    /* ------------------------------------------------------------------ *
     *  Pairing state                                                      *
     * ------------------------------------------------------------------ */
    struct Pairing {
        uint256 tokenId;
        uint64 expiresAt; // from the WorkerAuthorization; now enforced on-chain here
        uint64 authEpoch; // operator-key generation this pairing was made under
        uint64 custodyEpoch; // this seat's custody generation when the pairing was made
        bool exists;
    }

    mapping(bytes32 => Pairing) private _pairing; // digest => pairing (only authorizeWorker writes it — I4)
    uint64 public authEpoch; // ++ on any operator CHANGE → retires EVERY live pairing (clean slate)
    mapping(uint256 => uint64) public custodyEpoch; // tokenId => ++ on withdrawSeat (a re-deposit won't re-arm)
    mapping(uint256 => uint256) public agentIdOf; // tokenId => ERC-8004 agentId registered via this vault (0 = none)

    /* ------------------------------------------------------------------ *
     *  Events                                                             *
     * ------------------------------------------------------------------ */
    event SeatDeposited(uint256 indexed tokenId, address indexed from);
    event WorkerAuthorized(uint256 indexed tokenId, bytes32 deviceKey, bytes32 digest);
    event WorkerAuthorizationRevoked(bytes32 indexed digest);
    event AgentRegistered(uint256 indexed tokenId, uint256 agentId);
    event AgentURIUpdated(uint256 indexed tokenId, uint256 indexed agentId, string agentURI);
    event Swept(address indexed token, uint256 amount, address indexed to);
    event SeatWithdrawn(uint256 indexed tokenId, address indexed to);
    event SeatOperatorUpdated(address indexed operator);
    event RewardSinkUpdated(address indexed sink);
    event ERC721Rescued(address indexed token, uint256 indexed tokenId, address indexed to);

    /* ------------------------------------------------------------------ *
     *  Errors                                                             *
     * ------------------------------------------------------------------ */
    error NotSeatOperator();
    error NotSeatCollection();
    error WrongWallet();
    error AuthorizationExpired();
    error NotNFTOwner();
    error CannotSweepSeats();
    error ZeroAddress();
    error OwnershipCannotBeRenounced();
    error CannotRescueSeats();
    error ETHSweepFailed();
    error AlreadyRegistered();
    error NotRegistered();

    modifier onlySeatOperator() {
        if (msg.sender != seatOperator && msg.sender != owner()) revert NotSeatOperator();
        _;
    }

    constructor(
        address owner_, // the TimelockController
        IERC721 seatCollection_,
        IImdAgentAdapter agentAdapter_,
        IEnsReverseRegistrar ensReverseRegistrar_,
        address rewardSink_
    ) Ownable(owner_) {
        if (rewardSink_ == address(0)) revert ZeroAddress();
        if (address(seatCollection_) == address(0)) revert ZeroAddress();
        if (address(agentAdapter_) == address(0)) revert ZeroAddress();
        seatCollection = seatCollection_;
        agentAdapter = agentAdapter_;
        ensReverseRegistrar = ensReverseRegistrar_;
        rewardSink = rewardSink_;
        emit RewardSinkUpdated(rewardSink_);
    }

    /* ================================================================== *
     *  DEPOSITS — open, instant                                          *
     * ================================================================== */
    /// @notice Accept seat NFTs. Only the identity.md collection is accepted (stray NFTs are rejected).
    function onERC721Received(address, address from, uint256 tokenId, bytes calldata)
        external
        returns (bytes4)
    {
        if (msg.sender != address(seatCollection)) revert NotSeatCollection();
        emit SeatDeposited(tokenId, from);
        return IERC721Receiver.onERC721Received.selector;
    }

    /* ================================================================== *
     *  OPERATION — scoped operator (pair/run only, NEVER move)           *
     * ================================================================== */
    /// @notice Approve an IMD WorkerAuthorization so isValidSignature accepts it. The operator cannot pass
    ///         an arbitrary hash: the struct is validated and the digest computed here (I4 / §8.1).
    /// @dev    Then POST /pair/complete with the message and any signature bytes (e.g. "0x").
    function authorizeWorker(WorkerAuthorization calldata auth)
        external
        onlySeatOperator
        returns (bytes32 digest)
    {
        if (auth.wallet != address(this)) revert WrongWallet();
        if (auth.expiresAt <= block.timestamp) revert AuthorizationExpired();
        if (seatCollection.ownerOf(auth.tokenId) != address(this)) revert NotNFTOwner();
        digest = workerAuthorizationDigest(auth);
        _pairing[digest] = Pairing({
            tokenId: auth.tokenId,
            expiresAt: auth.expiresAt,
            authEpoch: authEpoch,
            custodyEpoch: custodyEpoch[auth.tokenId],
            exists: true
        });
        emit WorkerAuthorized(auth.tokenId, auth.deviceKey, digest);
    }

    /// @notice Revoke a previously approved WorkerAuthorization digest.
    function revokeWorkerAuthorization(bytes32 digest) external onlySeatOperator {
        delete _pairing[digest];
        emit WorkerAuthorizationRevoked(digest);
    }

    /// @notice Register an ERC-8004 agent for a held seat (needed once for a never-registered seat).
    /// @dev    Once per seat: a leaked operator key cannot spam duplicate agents. The owner (Timelock) may
    ///         force a re-registration, and can correct the URI via setAgentURI below.
    function registerAgent(uint256 tokenId, string calldata agentURI)
        external
        onlySeatOperator
        nonReentrant
        returns (uint256 agentId)
    {
        if (seatCollection.ownerOf(tokenId) != address(this)) revert NotNFTOwner();
        if (agentIdOf[tokenId] != 0 && msg.sender != owner()) revert AlreadyRegistered();
        // standard = 0 (ERC-721) on the live Adapter8004; first arg is uint8 (see IImdAgentAdapter).
        agentId = agentAdapter.register(0, address(seatCollection), tokenId, agentURI);
        agentIdOf[tokenId] = agentId;
        emit AgentRegistered(tokenId, agentId);
    }

    /// @notice Correct the agentURI of a seat registered through this vault (e.g. fix a URI set by a leaked
    ///         operator key). onlyOwner = the 48h Timelock. Scoped to this vault's own registrations.
    function setAgentURI(uint256 tokenId, string calldata agentURI) external onlyOwner {
        uint256 agentId = agentIdOf[tokenId];
        if (agentId == 0) revert NotRegistered();
        agentAdapter.setAgentURI(agentId, agentURI);
        emit AgentURIUpdated(tokenId, agentId, agentURI);
    }

    /// @notice EIP-712 digest of a WorkerAuthorization (domain bound to the seat collection, per IMD).
    function workerAuthorizationDigest(WorkerAuthorization calldata auth) public view returns (bytes32) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                WORKER_DOMAIN_TYPEHASH,
                WORKER_DOMAIN_NAME_HASH,
                WORKER_DOMAIN_VERSION_HASH,
                block.chainid,
                address(seatCollection)
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                WORKER_AUTHORIZATION_TYPEHASH,
                auth.deviceKey,
                auth.wallet,
                auth.tokenId,
                auth.nonce,
                auth.expiresAt,
                keccak256(bytes(auth.relayOrigin))
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /// @notice ERC-1271: VALID only for an approved WorkerAuthorization digest of a seat still held here,
    ///         while the pairing is unexpired and from the current operator key + custody period (I4 / I8).
    function isValidSignature(bytes32 hash, bytes calldata) external view returns (bytes4) {
        Pairing storage p = _pairing[hash];
        if (!p.exists) return ERC1271_INVALID; // only authorizeWorker ever writes this (I4)
        if (block.timestamp >= p.expiresAt) return ERC1271_INVALID; // expired on-chain (I8)
        if (p.authEpoch != authEpoch) return ERC1271_INVALID; // operator key was rotated (I8)
        if (p.custodyEpoch != custodyEpoch[p.tokenId]) return ERC1271_INVALID; // seat was withdrawn (I8)
        if (seatCollection.ownerOf(p.tokenId) != address(this)) return ERC1271_INVALID; // not held
        return ERC1271_VALID;
    }

    /// @notice Live view for keepers/tests: whether a digest is CURRENTLY a valid pairing, and its tokenId.
    ///         `authorized` folds in expiry + operator-rotation + custody freshness (ownership is checked
    ///         live in isValidSignature). The explicit bool disambiguates a real pairing for tokenId 0.
    function authorizedTokenId(bytes32 digest) external view returns (bool authorized, uint256 tokenId) {
        Pairing storage p = _pairing[digest];
        tokenId = p.tokenId;
        authorized = p.exists && block.timestamp < p.expiresAt && p.authEpoch == authEpoch
            && p.custodyEpoch == custodyEpoch[p.tokenId];
    }

    /* ================================================================== *
     *  EARNINGS — free out, to the fixed sink, never a seat             *
     * ================================================================== */
    /// @notice Push earned ERC-20s (IMD + launch tokens) to rewardSink. Permissionless; reverts if any
    ///         token is the seat collection. Cannot move a seat (ERC-20 path, fixed destination).
    function sweepEarnings(address[] calldata tokens) external nonReentrant {
        address sink = rewardSink;
        for (uint256 i; i < tokens.length; ++i) {
            address token = tokens[i];
            if (token == address(seatCollection)) revert CannotSweepSeats();
            uint256 bal = IERC20(token).balanceOf(address(this));
            if (bal != 0) {
                IERC20(token).safeTransfer(sink, bal);
                emit Swept(token, bal, sink);
            }
        }
    }

    /// @notice Accept ETH so an ETH-paying integration can pay the seat's wallet without reverting.
    receive() external payable {}

    /// @notice Push any ETH the vault holds to rewardSink. Permissionless with a fixed destination, exactly
    ///         like sweepEarnings; never touches a seat.
    function sweepETH() external nonReentrant {
        uint256 bal = address(this).balance;
        if (bal != 0) {
            (bool ok,) = rewardSink.call{value: bal}("");
            if (!ok) revert ETHSweepFailed();
            emit Swept(address(0), bal, rewardSink);
        }
    }

    /* ================================================================== *
     *  EXIT & CONFIG — owner = Timelock (delayed + public)              *
     * ================================================================== */
    /// @notice The ONLY way a seat leaves. onlyOwner = the 48h Timelock, so every exit is queued publicly.
    function withdrawSeat(uint256 tokenId, address to) external onlyOwner {
        unchecked { ++custodyEpoch[tokenId]; } // retire this seat's pairings; a re-deposit won't re-arm (I8)
        seatCollection.safeTransferFrom(address(this), to, tokenId);
        emit SeatWithdrawn(tokenId, to);
    }

    /// @notice Rotate / disable (address(0)) the operator hot key. ANY change clean-slates every live pairing.
    function setSeatOperator(address operator) external onlyOwner {
        if (operator == seatOperator) return; // no-op: don't needlessly retire every live pairing
        seatOperator = operator;
        unchecked { ++authEpoch; } // any operator change retires EVERY live pairing (clean slate), not just the old key's (I8)
        emit SeatOperatorUpdated(operator);
    }

    /// @notice Change where swept earnings go.
    function setRewardSink(address sink) external onlyOwner {
        if (sink == address(0)) revert ZeroAddress();
        rewardSink = sink;
        emit RewardSinkUpdated(sink);
    }

    /// @notice Disabled: renouncing would strand every custodied seat forever (I1/I6). Ownership can still be
    ///         handed to a NEW Timelock via transferOwnership + acceptOwnership (two-step).
    function renounceOwnership() public pure override {
        revert OwnershipCannotBeRenounced();
    }

    /// @notice Recover a NON-seat NFT sent here by mistake (seats can only leave via withdrawSeat). onlyOwner.
    function rescueERC721(IERC721 token, uint256 tokenId, address to) external onlyOwner {
        if (address(token) == address(seatCollection)) revert CannotRescueSeats();
        token.safeTransferFrom(address(this), to, tokenId);
        emit ERC721Rescued(address(token), tokenId, to);
    }

    /* ================================================================== *
     *  ENS branding — cosmetic, owner-gated                             *
     * ================================================================== */
    /// @notice Set the vault's primary ENS name so it shows branded on OpenSea / explorers.
    function setEnsName(string calldata name) external onlyOwner returns (bytes32) {
        return ensReverseRegistrar.setName(name);
    }
}
