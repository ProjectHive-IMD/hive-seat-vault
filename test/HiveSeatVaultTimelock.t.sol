// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {HiveSeatVault, IImdAgentAdapter, IEnsReverseRegistrar} from "../src/HiveSeatVault.sol";

contract TLSeat is ERC721 {
    constructor() ERC721("identity.md", "IDMD") {}
    function mint(address to, uint256 id) external { _mint(to, id); }
}

/**
 * Integration test: the vault owned by a REAL 48h OpenZeppelin TimelockController (admin renounced),
 * exactly as the deploy script wires it. Proves that a seat exit is a public, 48h-delayed operation —
 * the backbone of the "the team can't rug the seats" guarantee (audit finding #3).
 */
contract HiveSeatVaultTimelockTest is Test {
    TimelockController timelock;
    HiveSeatVault vault;
    TLSeat seat;

    address proposer = makeAddr("proposer"); // the team key / multisig that queues ops
    address executor = makeAddr("executor");
    address holder = makeAddr("holder");
    address sink = makeAddr("sink");
    uint256 constant DELAY = 48 hours;
    uint256 constant SEAT_ID = 1343;

    function setUp() public {
        vm.warp(1_700_000_000);
        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        address[] memory executors = new address[](1);
        executors[0] = executor;
        timelock = new TimelockController(DELAY, proposers, executors, address(0)); // admin renounced

        seat = new TLSeat();
        vault = new HiveSeatVault(
            address(timelock),
            IERC721(address(seat)),
            IImdAgentAdapter(makeAddr("adapter")),
            IEnsReverseRegistrar(address(0)),
            sink
        );
        seat.mint(holder, SEAT_ID);
        vm.prank(holder);
        seat.safeTransferFrom(holder, address(vault), SEAT_ID);
    }

    function test_timelock_is_48h_and_owns_vault() public view {
        assertEq(timelock.getMinDelay(), DELAY);
        assertEq(vault.owner(), address(timelock));
    }

    /// A seat exit must be queued publicly and executable only after 48h.
    function test_withdraw_requires_48h_delay() public {
        bytes memory data = abi.encodeCall(HiveSeatVault.withdrawSeat, (SEAT_ID, holder));
        bytes32 salt = bytes32("hive-withdraw-1343");

        vm.prank(proposer);
        timelock.schedule(address(vault), 0, data, bytes32(0), salt, DELAY);

        // before the delay: execution reverts, the seat stays in the vault
        vm.prank(executor);
        vm.expectRevert();
        timelock.execute(address(vault), 0, data, bytes32(0), salt);
        assertEq(seat.ownerOf(SEAT_ID), address(vault));

        // after 48h: it executes and the seat leaves
        vm.warp(block.timestamp + DELAY);
        vm.prank(executor);
        timelock.execute(address(vault), 0, data, bytes32(0), salt);
        assertEq(seat.ownerOf(SEAT_ID), holder);
    }

    /// Only the proposer (team key / multisig) can queue an operation.
    function test_only_proposer_can_queue() public {
        bytes memory data = abi.encodeCall(HiveSeatVault.withdrawSeat, (SEAT_ID, holder));
        vm.prank(holder);
        vm.expectRevert();
        timelock.schedule(address(vault), 0, data, bytes32(0), bytes32("x"), DELAY);
    }

    /// Config changes (e.g. rotating the operator) are delayed too, not just seat exits.
    function test_setSeatOperator_also_delayed() public {
        address op = makeAddr("op");
        bytes memory data = abi.encodeCall(HiveSeatVault.setSeatOperator, (op));
        bytes32 salt = bytes32("set-op");

        vm.prank(proposer);
        timelock.schedule(address(vault), 0, data, bytes32(0), salt, DELAY);
        vm.prank(executor);
        vm.expectRevert();
        timelock.execute(address(vault), 0, data, bytes32(0), salt);

        vm.warp(block.timestamp + DELAY);
        vm.prank(executor);
        timelock.execute(address(vault), 0, data, bytes32(0), salt);
        assertEq(vault.seatOperator(), op);
    }

    /* ---- audit 41fa0208 #2: self-administration + a separate cancel-only guardian ---- */

    /// Shortening the delay is possible only through a self-call that is ITSELF queued for the full 48h.
    function test_delay_change_itself_waits_48h() public {
        bytes memory data = abi.encodeCall(TimelockController.updateDelay, (0));
        bytes32 salt = bytes32("zero-delay");
        vm.prank(proposer);
        timelock.schedule(address(timelock), 0, data, bytes32(0), salt, DELAY);
        vm.prank(executor);
        vm.expectRevert();
        timelock.execute(address(timelock), 0, data, bytes32(0), salt);
        assertEq(timelock.getMinDelay(), DELAY);
    }

    /// The routeERC20 exit is owner-only, so it is delayed like every other owner action.
    function test_routeERC20_requires_48h() public {
        bytes memory data = abi.encodeCall(HiveSeatVault.routeERC20, (IERC20(makeAddr("token")), holder, 1));
        bytes32 salt = bytes32("route");
        vm.prank(proposer);
        timelock.schedule(address(vault), 0, data, bytes32(0), salt, DELAY);
        vm.prank(executor);
        vm.expectRevert();
        timelock.execute(address(vault), 0, data, bytes32(0), salt);
    }

    function _guardedTimelock(address guardian) internal returns (TimelockController tl, HiveSeatVault v) {
        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        address[] memory executors = new address[](1);
        executors[0] = executor;
        // exactly as the deploy script does it: temporary admin -> grant CANCELLER to guardian -> renounce
        tl = new TimelockController(DELAY, proposers, executors, address(this));
        tl.grantRole(tl.CANCELLER_ROLE(), guardian);
        tl.renounceRole(tl.DEFAULT_ADMIN_ROLE(), address(this));
        v = new HiveSeatVault(address(tl), IERC721(address(seat)), IImdAgentAdapter(makeAddr("adapter")), IEnsReverseRegistrar(address(0)), sink);
        seat.mint(holder, 777);
        vm.prank(holder);
        seat.safeTransferFrom(holder, address(v), 777);
    }

    /// A separate guardian can cancel a queued withdrawal from a leaked proposer key, but can't queue or run anything.
    function test_guardian_cancels_hostile_withdraw() public {
        address guardian = makeAddr("guardian");
        (TimelockController tl, HiveSeatVault v) = _guardedTimelock(guardian);
        assertFalse(tl.hasRole(tl.DEFAULT_ADMIN_ROLE(), address(this)));
        assertFalse(tl.hasRole(tl.PROPOSER_ROLE(), guardian));

        bytes memory data = abi.encodeCall(HiveSeatVault.withdrawSeat, (777, proposer));
        bytes32 salt = bytes32("hostile");
        vm.prank(proposer);
        tl.schedule(address(v), 0, data, bytes32(0), salt, DELAY);
        bytes32 id = tl.hashOperation(address(v), 0, data, bytes32(0), salt);

        vm.prank(guardian);
        tl.cancel(id);
        vm.warp(block.timestamp + DELAY);
        vm.prank(executor);
        vm.expectRevert();
        tl.execute(address(v), 0, data, bytes32(0), salt);
        assertEq(seat.ownerOf(777), address(v));

        // the guardian itself cannot queue anything
        vm.prank(guardian);
        vm.expectRevert();
        tl.schedule(address(v), 0, data, bytes32(0), bytes32("g"), DELAY);
    }

    /// ... and a queued delay change (the "zero the delay first" route) can be cancelled the same way.
    function test_guardian_cancels_delay_change() public {
        address guardian = makeAddr("guardian");
        (TimelockController tl,) = _guardedTimelock(guardian);
        bytes memory data = abi.encodeCall(TimelockController.updateDelay, (0));
        bytes32 salt = bytes32("zero");
        vm.prank(proposer);
        tl.schedule(address(tl), 0, data, bytes32(0), salt, DELAY);
        bytes32 id = tl.hashOperation(address(tl), 0, data, bytes32(0), salt);
        vm.prank(guardian);
        tl.cancel(id);
        vm.warp(block.timestamp + DELAY);
        vm.prank(executor);
        vm.expectRevert();
        tl.execute(address(tl), 0, data, bytes32(0), salt);
        assertEq(tl.getMinDelay(), DELAY);
    }
}
