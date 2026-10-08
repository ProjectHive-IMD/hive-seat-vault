// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {HiveSeatVault, IImdAgentAdapter, IEnsReverseRegistrar} from "../src/HiveSeatVault.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
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

contract MockAdapter is IImdAgentAdapter {
    uint256 public n = 52000;
    function register(uint256, address, uint256, string calldata) external returns (uint256) {
        return ++n;
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
        assertEq(vault.authorizedTokenId(digest), SEAT_ID);
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
}
