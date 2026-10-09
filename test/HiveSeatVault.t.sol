// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {HiveSeatVault, IImdAgentAdapter, IEnsReverseRegistrar} from "../src/HiveSeatVault.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/* ----------------------------- mocks ----------------------------- */
contract MockSeat is ERC721 {
    constructor() ERC721("identity.md", "IMD") {}
    function mint(address to, uint256 id) external { _mint(to, id); }
}

contract MockOtherNft is ERC721 {
    constructor() ERC721("Other", "OTH") {}
    function mint(address to, uint256 id) external { _mint(to, id); }
}

contract MockToken is ERC20 {
    constructor() ERC20("IMD Token", "IMD") {}
    function mint(address to, uint256 amt) external { _mint(to, amt); }
}

/// Mimics a restricted IMD launch token (e.g. IMDSeatStrategy's): transfers only allowed to/from `router`.
contract MockRestrictedToken is ERC20 {
    address public immutable router;
    error InvalidTransfer();
    constructor(address r) ERC20("Launch", "LT") { router = r; }
    function mint(address to, uint256 amt) external { _mint(to, amt); }
    function _update(address from, address to, uint256 v) internal override {
        if (from != address(0) && from != router && to != router) revert InvalidTransfer();
        super._update(from, to, v);
    }
}

contract MockAdapter is IImdAgentAdapter {
    uint256 public n = 52000;
    mapping(uint256 => string) public uriOf;
    // matches the live Adapter8004 ABI: first arg is uint8 (TokenStandard enum)
    function register(uint8, address, uint256, string calldata uri) external returns (uint256) {
        uriOf[++n] = uri;
        return n;
    }
    function setAgentURI(uint256 agentId, string calldata uri) external {
        uriOf[agentId] = uri;
    }
}

contract MockReverse is IEnsReverseRegistrar {
    string public last;
    function setName(string calldata name) external returns (bytes32) {
        last = name;
        return keccak256(bytes(name));
    }
}

/* ----------------------------- tests ----------------------------- */
contract HiveSeatVaultTest is Test {
    HiveSeatVault vault;
    MockSeat seat;
    MockToken imd;
    MockAdapter adapter;
    MockReverse ens;

    address timelock = makeAddr("timelock"); // stands in for the TimelockController (owner)
    address operator = makeAddr("operator"); // scoped hot key
    address sink = makeAddr("rewardSink");
    address treasury = makeAddr("treasury"); // 0x84b3 equivalent
    address attacker = makeAddr("attacker");

    uint256 constant SEAT_ID = 1343;

    function setUp() public {
        vm.warp(1_700_000_000); // non-zero time for expiry checks
        seat = new MockSeat();
        imd = new MockToken();
        adapter = new MockAdapter();
        ens = new MockReverse();
        vault = new HiveSeatVault(timelock, IERC721(address(seat)), adapter, ens, sink);
        vm.prank(timelock);
        vault.setSeatOperator(operator);

        // treasury deposits a seat into the vault
        seat.mint(treasury, SEAT_ID);
        vm.prank(treasury);
        seat.safeTransferFrom(treasury, address(vault), SEAT_ID);
    }

    function _auth(uint256 tokenId) internal view returns (HiveSeatVault.WorkerAuthorization memory a) {
        a.deviceKey = keccak256("device-key");
        a.wallet = address(vault);
        a.tokenId = tokenId;
        a.nonce = keccak256("nonce");
        a.expiresAt = uint64(block.timestamp + 1 hours);
        a.relayOrigin = "https://api.imd.fun";
    }

    /* ---- deposits ---- */
    function test_deposit_recorded() public view {
        assertEq(seat.ownerOf(SEAT_ID), address(vault));
    }

    function test_rejects_foreign_collection() public {
        MockOtherNft other = new MockOtherNft();
        other.mint(treasury, 7);
        vm.prank(treasury);
        vm.expectRevert(HiveSeatVault.NotSeatCollection.selector);
        other.safeTransferFrom(treasury, address(vault), 7);
    }

    /* ---- operation / pairing (I3, I4) ---- */
    function test_only_operator_or_owner_can_authorize() public {
        vm.prank(attacker);
        vm.expectRevert(HiveSeatVault.NotSeatOperator.selector);
        vault.authorizeWorker(_auth(SEAT_ID));
    }

    function test_authorize_then_isValidSignature_valid() public {
        vm.prank(operator);
        bytes32 digest = vault.authorizeWorker(_auth(SEAT_ID));
        assertEq(vault.isValidSignature(digest, ""), bytes4(0x1626ba7e));
        (bool ok, uint256 tid) = vault.authorizedTokenId(digest);
        assertTrue(ok);
        assertEq(tid, SEAT_ID);
    }

    function test_random_hash_is_invalid() public view {
        assertEq(vault.isValidSignature(keccak256("not a worker auth"), ""), bytes4(0xffffffff));
    }

    function test_authorize_reverts_if_not_owned() public {
        seat.mint(attacker, 777); // exists, but the vault does not hold it
        vm.prank(operator);
        vm.expectRevert(HiveSeatVault.NotNFTOwner.selector);
        vault.authorizeWorker(_auth(777));
    }

    function test_authorize_reverts_wrong_wallet() public {
        HiveSeatVault.WorkerAuthorization memory a = _auth(SEAT_ID);
        a.wallet = attacker;
        vm.prank(operator);
        vm.expectRevert(HiveSeatVault.WrongWallet.selector);
        vault.authorizeWorker(a);
    }

    function test_authorize_reverts_expired() public {
        HiveSeatVault.WorkerAuthorization memory a = _auth(SEAT_ID);
        a.expiresAt = uint64(block.timestamp - 1);
        vm.prank(operator);
        vm.expectRevert(HiveSeatVault.AuthorizationExpired.selector);
        vault.authorizeWorker(a);
    }

    function test_signature_invalid_after_seat_leaves() public {
        vm.prank(operator);
        bytes32 digest = vault.authorizeWorker(_auth(SEAT_ID));
        assertEq(vault.isValidSignature(digest, ""), bytes4(0x1626ba7e));
        vm.prank(timelock);
        vault.withdrawSeat(SEAT_ID, treasury);
        // digest is still stored but the vault no longer owns the seat -> INVALID
        assertEq(vault.isValidSignature(digest, ""), bytes4(0xffffffff));
    }

    /* ---- §8.1 THE CRUX: operator cannot forge a sale signature ---- */
    function test_operator_cannot_make_vault_sign_a_sale() public {
        // simulate a Seaport order hash that would list the seat for sale
        bytes32 seaportOrderHash = keccak256("Seaport: SELL seat 1343 for 0.01 ETH");
        // it is invalid now...
        assertEq(vault.isValidSignature(seaportOrderHash, ""), bytes4(0xffffffff));
        // ...the operator authorizes a legitimate worker (its only power)...
        vm.prank(operator);
        vault.authorizeWorker(_auth(SEAT_ID));
        // ...and the sale hash is STILL invalid. There is no function that can insert it.
        assertEq(vault.isValidSignature(seaportOrderHash, ""), bytes4(0xffffffff));
    }

    /* ---- exit (I1, I6) ---- */
    function test_operator_cannot_withdraw() public {
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, operator));
        vault.withdrawSeat(SEAT_ID, operator);
    }

    function test_owner_withdraws() public {
        vm.prank(timelock);
        vault.withdrawSeat(SEAT_ID, treasury);
        assertEq(seat.ownerOf(SEAT_ID), treasury);
    }

    /* ---- earnings (I5) ---- */
    function test_sweep_earnings_to_sink_is_permissionless() public {
        imd.mint(address(vault), 100e18);
        address[] memory t = new address[](1);
        t[0] = address(imd);
        vm.prank(attacker); // anyone can trigger; destination is fixed
        vault.sweepEarnings(t);
        assertEq(imd.balanceOf(sink), 100e18);
        assertEq(imd.balanceOf(address(vault)), 0);
    }

    function test_sweep_cannot_touch_seats() public {
        address[] memory t = new address[](1);
        t[0] = address(seat);
        vm.expectRevert(HiveSeatVault.CannotSweepSeats.selector);
        vault.sweepEarnings(t);
        // seat untouched
        assertEq(seat.ownerOf(SEAT_ID), address(vault));
    }

    /* ---- config (I6) ---- */
    function test_set_reward_sink_only_owner_and_nonzero() public {
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attacker));
        vault.setRewardSink(attacker);

        vm.prank(timelock);
        vm.expectRevert(HiveSeatVault.ZeroAddress.selector);
        vault.setRewardSink(address(0));

        address newSink = makeAddr("newSink");
        vm.prank(timelock);
        vault.setRewardSink(newSink);
        assertEq(vault.rewardSink(), newSink);
    }

    function test_set_operator_only_owner() public {
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attacker));
        vault.setSeatOperator(attacker);
    }

    /* ---- registration ---- */
    function test_register_agent() public {
        vm.prank(operator);
        uint256 id = vault.registerAgent(SEAT_ID, "ipfs://agent");
        assertGt(id, 0);
    }

    function test_register_agent_reverts_if_not_owned() public {
        seat.mint(attacker, 778); // exists, not held by the vault
        vm.prank(operator);
        vm.expectRevert(HiveSeatVault.NotNFTOwner.selector);
        vault.registerAgent(778, "ipfs://agent");
    }

    /* ---- ENS branding (I6) ---- */
    function test_set_ens_name_only_owner() public {
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attacker));
        vault.setEnsName("hivevault.eth");

        vm.prank(timelock);
        vault.setEnsName("hivevault.eth");
        assertEq(ens.last(), "hivevault.eth");
    }

    /* ---- pairing freshness: finding #2 / I8 ---- */
    function test_pairing_expires_on_chain() public {
        vm.prank(operator);
        bytes32 digest = vault.authorizeWorker(_auth(SEAT_ID));
        assertEq(vault.isValidSignature(digest, ""), bytes4(0x1626ba7e));
        vm.warp(block.timestamp + 2 hours); // past expiresAt (set to now + 1h)
        assertEq(vault.isValidSignature(digest, ""), bytes4(0xffffffff));
        (bool ok,) = vault.authorizedTokenId(digest);
        assertFalse(ok);
    }

    function test_rotating_operator_retires_pairings() public {
        vm.prank(operator);
        bytes32 digest = vault.authorizeWorker(_auth(SEAT_ID));
        assertEq(vault.isValidSignature(digest, ""), bytes4(0x1626ba7e));
        // rotating the hot key neutralises a leaked key immediately — even before the pairing's own expiry
        vm.prank(timelock);
        vault.setSeatOperator(makeAddr("newOperator"));
        assertEq(vault.isValidSignature(digest, ""), bytes4(0xffffffff));
    }

    function test_redeposit_does_not_rearm_old_pairing() public {
        vm.prank(operator);
        bytes32 digest = vault.authorizeWorker(_auth(SEAT_ID));
        vm.prank(timelock);
        vault.withdrawSeat(SEAT_ID, treasury);
        assertEq(vault.isValidSignature(digest, ""), bytes4(0xffffffff));
        // re-deposit the same seat: the old digest must NOT silently come back to life
        vm.prank(treasury);
        seat.safeTransferFrom(treasury, address(vault), SEAT_ID);
        assertEq(vault.isValidSignature(digest, ""), bytes4(0xffffffff));
    }

    /* ---- ownership hardening: finding #3 ---- */
    function test_renounce_ownership_disabled() public {
        vm.prank(timelock);
        vm.expectRevert(HiveSeatVault.OwnershipCannotBeRenounced.selector);
        vault.renounceOwnership();
        assertEq(vault.owner(), timelock);
    }

    /* ---- ETH path + NFT rescue: finding #4 ---- */
    function test_eth_received_and_swept_to_sink() public {
        vm.deal(address(this), 1 ether);
        (bool sent,) = address(vault).call{value: 1 ether}("");
        assertTrue(sent, "vault must accept ETH");
        assertEq(address(vault).balance, 1 ether);
        vault.sweepETH(); // permissionless, fixed destination
        assertEq(address(vault).balance, 0);
        assertEq(sink.balance, 1 ether);
    }

    function test_rescue_foreign_nft_but_never_seats() public {
        MockOtherNft other = new MockOtherNft();
        other.mint(address(this), 7);
        other.transferFrom(address(this), address(vault), 7); // unsafe path bypasses onERC721Received
        assertEq(other.ownerOf(7), address(vault));
        // owner (timelock) can rescue a stray NFT...
        vm.prank(timelock);
        vault.rescueERC721(IERC721(address(other)), 7, treasury);
        assertEq(other.ownerOf(7), treasury);
        // ...but rescue can NEVER be used on the seat collection (I1)
        vm.prank(timelock);
        vm.expectRevert(HiveSeatVault.CannotRescueSeats.selector);
        vault.rescueERC721(IERC721(address(seat)), SEAT_ID, treasury);
        assertEq(seat.ownerOf(SEAT_ID), address(vault));
    }

    function test_rescue_only_owner() public {
        MockOtherNft other = new MockOtherNft();
        other.mint(address(vault), 8);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attacker));
        vault.rescueERC721(IERC721(address(other)), 8, attacker);
    }

    /* ---- registration hardening: finding #1 ---- */
    function test_register_agent_rejects_duplicate() public {
        vm.prank(operator);
        uint256 id1 = vault.registerAgent(SEAT_ID, "ipfs://one");
        assertEq(vault.agentIdOf(SEAT_ID), id1);
        // a leaked operator key cannot spam a second agent for the same seat
        vm.prank(operator);
        vm.expectRevert(HiveSeatVault.AlreadyRegistered.selector);
        vault.registerAgent(SEAT_ID, "ipfs://two");
        // ...but the owner (Timelock) may force a re-register if ever needed
        vm.prank(timelock);
        uint256 id2 = vault.registerAgent(SEAT_ID, "ipfs://owner");
        assertGt(id2, id1);
    }

    function test_owner_can_correct_agent_uri() public {
        vm.prank(operator);
        uint256 id = vault.registerAgent(SEAT_ID, "ipfs://poison");
        assertEq(adapter.uriOf(id), "ipfs://poison");
        // operator cannot correct it
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, operator));
        vault.setAgentURI(SEAT_ID, "ipfs://good");
        // owner (Timelock) can
        vm.prank(timelock);
        vault.setAgentURI(SEAT_ID, "ipfs://good");
        assertEq(adapter.uriOf(id), "ipfs://good");
    }

    function test_setAgentURI_reverts_if_not_registered() public {
        vm.prank(timelock);
        vm.expectRevert(HiveSeatVault.NotRegistered.selector);
        vault.setAgentURI(SEAT_ID, "ipfs://x");
    }

    /* ---- operator no-op reset: finding #2 ---- */
    function test_same_operator_reset_is_noop() public {
        vm.prank(operator);
        bytes32 digest = vault.authorizeWorker(_auth(SEAT_ID));
        assertEq(vault.isValidSignature(digest, ""), bytes4(0x1626ba7e));
        // re-setting the SAME operator address must NOT wipe live pairings
        vm.prank(timelock);
        vault.setSeatOperator(operator);
        assertEq(vault.isValidSignature(digest, ""), bytes4(0x1626ba7e));
    }

    /* ---- constructor zero-checks: finding #3 ---- */
    function test_constructor_rejects_zero_collection() public {
        vm.expectRevert(HiveSeatVault.ZeroAddress.selector);
        new HiveSeatVault(timelock, IERC721(address(0)), adapter, ens, sink);
    }

    function test_constructor_rejects_zero_adapter() public {
        vm.expectRevert(HiveSeatVault.ZeroAddress.selector);
        new HiveSeatVault(timelock, IERC721(address(seat)), IImdAgentAdapter(address(0)), ens, sink);
    }

    /* ---- final-audit low #1: owner can correct an orphaned agent by id ---- */
    function test_owner_can_correct_orphaned_agent_by_id() public {
        vm.prank(operator);
        uint256 idA = vault.registerAgent(SEAT_ID, "ipfs://poison");
        // owner force re-registers -> agentIdOf points at B, A is orphaned
        vm.prank(timelock);
        uint256 idB = vault.registerAgent(SEAT_ID, "ipfs://owner");
        assertEq(vault.agentIdOf(SEAT_ID), idB);
        // the by-tokenId correction only reaches the latest (B)
        vm.prank(timelock);
        vault.setAgentURI(SEAT_ID, "ipfs://good");
        assertEq(adapter.uriOf(idB), "ipfs://good");
        assertEq(adapter.uriOf(idA), "ipfs://poison");
        // ...but setAgentURIById reaches the orphaned first agent A
        vm.prank(timelock);
        vault.setAgentURIById(idA, "ipfs://fixed");
        assertEq(adapter.uriOf(idA), "ipfs://fixed");
    }

    function test_setAgentURIById_only_owner() public {
        vm.prank(operator);
        uint256 id = vault.registerAgent(SEAT_ID, "ipfs://x");
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, operator));
        vault.setAgentURIById(id, "ipfs://y");
    }

    /* ---- final-audit low #2: ownership handover retires pairings ---- */
    function test_ownership_handover_retires_pairings() public {
        // the owner (Timelock) makes a pairing
        vm.prank(timelock);
        bytes32 digest = vault.authorizeWorker(_auth(SEAT_ID));
        assertEq(vault.isValidSignature(digest, ""), bytes4(0x1626ba7e));
        // hand ownership to a new Timelock (two-step)
        address timelock2 = makeAddr("timelock2");
        vm.prank(timelock);
        vault.transferOwnership(timelock2);
        vm.prank(timelock2);
        vault.acceptOwnership();
        assertEq(vault.owner(), timelock2);
        // the previous owner's pairing is retired by the handover (authEpoch bumped)
        assertEq(vault.isValidSignature(digest, ""), bytes4(0xffffffff));
    }

    /* ---- final-audit info #7: setEnsName guard ---- */
    function test_setEnsName_reverts_without_registrar() public {
        HiveSeatVault v2 =
            new HiveSeatVault(timelock, IERC721(address(seat)), adapter, IEnsReverseRegistrar(address(0)), sink);
        vm.prank(timelock);
        vm.expectRevert(HiveSeatVault.EnsNotConfigured.selector);
        v2.setEnsName("hive.eth");
    }

    /* ---- routeERC20 (audit 41fa0208 #1: restricted launch tokens) ---- */
    function test_restricted_launch_token_cannot_sweep_but_owner_can_route() public {
        address router = makeAddr("launchRouter");
        MockRestrictedToken lt = new MockRestrictedToken(router);
        lt.mint(address(vault), 500e18);
        address[] memory t = new address[](1);
        t[0] = address(lt);
        vm.expectRevert(MockRestrictedToken.InvalidTransfer.selector); // plain sweep to the sink is refused
        vault.sweepEarnings(t);
        assertEq(lt.balanceOf(address(vault)), 500e18); // stuck but safe

        vm.prank(timelock); // the owner (= Timelock, so queued 48h in real life) routes it to the allowed router
        vault.routeERC20(lt, router, 500e18);
        assertEq(lt.balanceOf(router), 500e18);
        assertEq(lt.balanceOf(address(vault)), 0);
    }

    function test_routeERC20_only_owner() public {
        imd.mint(address(vault), 10e18);
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, operator));
        vault.routeERC20(imd, operator, 10e18);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attacker));
        vault.routeERC20(imd, attacker, 10e18);
        assertEq(imd.balanceOf(address(vault)), 10e18);
    }

    function test_routeERC20_never_touches_seats_or_zero_address() public {
        vm.prank(timelock);
        vm.expectRevert(HiveSeatVault.CannotSweepSeats.selector);
        vault.routeERC20(IERC20(address(seat)), timelock, SEAT_ID);
        assertEq(seat.ownerOf(SEAT_ID), address(vault));

        imd.mint(address(vault), 1e18);
        vm.prank(timelock);
        vm.expectRevert(HiveSeatVault.ZeroAddress.selector);
        vault.routeERC20(imd, address(0), 1e18);
    }

    function test_routeERC20_partial_amount_and_event() public {
        imd.mint(address(vault), 10e18);
        address dest = makeAddr("dest");
        vm.expectEmit(true, true, false, true, address(vault));
        emit HiveSeatVault.ERC20Routed(address(imd), dest, 4e18);
        vm.prank(timelock);
        vault.routeERC20(imd, dest, 4e18);
        assertEq(imd.balanceOf(dest), 4e18);
        assertEq(imd.balanceOf(address(vault)), 6e18);
    }
}
