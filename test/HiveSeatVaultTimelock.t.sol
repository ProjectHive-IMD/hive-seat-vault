// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
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
}
