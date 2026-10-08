// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console2} from "forge-std/Test.sol";
import {HiveSeatVault, IImdAgentAdapter, IEnsReverseRegistrar} from "../src/HiveSeatVault.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

/// @dev The live, audited IMDSeatStrategy (proxy "IMD6900") — we compare our pairing math against it.
interface IRefStrategy {
    function workerAuthorizationDigest(HiveSeatVault.WorkerAuthorization calldata auth)
        external
        view
        returns (bytes32);
    function IMD_AGENT_ADAPTER() external view returns (address);
    function seatOperator() external view returns (address);
}

/**
 * Fork tests: prove the vault works against the REAL identity.md collection and that its ERC-1271
 * pairing digest is byte-identical to the live, IMD-accepted IMDSeatStrategy (so IMD will accept us too).
 * Run with network access; setUp forks mainnet itself.
 */
contract HiveSeatVaultForkTest is Test {
    address constant IMD_NFT = 0x0000eC93127BAA929E58E97dd0095A2BFb38ec1D; // identity.md collection
    address constant REF_STRATEGY = 0x0000198C940D8cD70Cb9ACeC5E3af8216ac57d2F; // IMDSeatStrategy proxy
    address constant TREASURY = 0x84b31CB3D205EfD2d20F29eA7ccaB1bc34326DdB; // Hive treasury (holds the seats)
    uint256 constant SEAT = 1343; // a Hive-owned seat in the treasury

    HiveSeatVault vault;
    address timelock = makeAddr("timelock");
    address operator = makeAddr("operator");
    address sink = makeAddr("sink");
    address realAdapter;

    function setUp() public {
        vm.createSelectFork(vm.envOr("ETH_RPC_URL", string("https://ethereum-rpc.publicnode.com")));
        realAdapter = IRefStrategy(REF_STRATEGY).IMD_AGENT_ADAPTER();
        console2.log("live IMD_AGENT_ADAPTER:", realAdapter);
        vault = new HiveSeatVault(
            timelock, IERC721(IMD_NFT), IImdAgentAdapter(realAdapter), IEnsReverseRegistrar(address(0)), sink
        );
        vm.prank(timelock);
        vault.setSeatOperator(operator);
    }

    function _auth() internal view returns (HiveSeatVault.WorkerAuthorization memory a) {
        a.deviceKey = keccak256("device-key");
        a.wallet = address(vault);
        a.tokenId = SEAT;
        a.nonce = keccak256("nonce");
        a.expiresAt = uint64(block.timestamp + 1 hours);
        a.relayOrigin = "https://api.imd.fun";
    }

    /// Our digest must equal the live, audited, IMD-accepted contract's for the same authorization.
    function test_fork_digest_matches_live_reference() public view {
        HiveSeatVault.WorkerAuthorization memory a = _auth();
        bytes32 ours = vault.workerAuthorizationDigest(a);
        bytes32 refDigest = IRefStrategy(REF_STRATEGY).workerAuthorizationDigest(a);
        assertEq(ours, refDigest, "pairing digest diverges from the audited reference");
    }

    /// Real seat, real collection: deposit -> operator authorizes -> ERC-1271 accepts.
    function test_fork_real_seat_pairs() public {
        vm.prank(TREASURY);
        IERC721(IMD_NFT).safeTransferFrom(TREASURY, address(vault), SEAT);
        assertEq(IERC721(IMD_NFT).ownerOf(SEAT), address(vault), "seat not custodied");

        vm.prank(operator);
        bytes32 digest = vault.authorizeWorker(_auth());
        assertEq(vault.isValidSignature(digest, ""), bytes4(0x1626ba7e), "IMD would reject this signature");
    }

    /// The seat can still only leave via the timelocked owner, even with a real collection.
    function test_fork_operator_cannot_withdraw_real_seat() public {
        vm.prank(TREASURY);
        IERC721(IMD_NFT).safeTransferFrom(TREASURY, address(vault), SEAT);
        vm.prank(operator);
        vm.expectRevert();
        vault.withdrawSeat(SEAT, operator);
        assertEq(IERC721(IMD_NFT).ownerOf(SEAT), address(vault));
    }
}
