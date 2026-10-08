// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script, console2} from "forge-std/Script.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {HiveSeatVault, IImdAgentAdapter, IEnsReverseRegistrar} from "../src/HiveSeatVault.sol";

/**
 * @notice Deploys a 48h TimelockController (admin renounced) and the HiveSeatVault it owns, so EVERY seat
 *         exit and config change is a public, 48h-delayed operation — the backbone of the anti-rug guarantee
 *         (addresses audit finding #3: nothing in the contract itself pins the owner to a real timelock).
 *
 *         Run against Ethereum mainnet, e.g.:
 *           HIVE_REWARD_SINK=0x... HIVE_TIMELOCK_PROPOSER=0x... \
 *           forge script script/DeployHiveSeatVault.s.sol --rpc-url $ETH_RPC_URL --broadcast
 *
 *         - admin = address(0): no one can shorten the delay or re-grant roles after deploy.
 *         - executor = address(0) (default): execution of a READY op is permissionless; only the proposer
 *           (the team key / multisig) can queue, and only after the 48h delay can anyone execute.
 */
contract DeployHiveSeatVault is Script {
    // identity.md mainnet addresses (collection is not a proxy; adapter = IMDSeatStrategy.IMD_AGENT_ADAPTER()).
    address constant SEAT_COLLECTION = 0x0000eC93127BAA929E58E97dd0095A2BFb38ec1D;
    address constant AGENT_ADAPTER = 0xde152AfB7db5373F34876E1499fbD893A82dD336;
    uint256 constant MIN_DELAY = 48 hours;

    function run() external returns (TimelockController timelock, HiveSeatVault vault) {
        address rewardSink = vm.envAddress("HIVE_REWARD_SINK"); // where swept earnings go
        address proposer = vm.envAddress("HIVE_TIMELOCK_PROPOSER"); // team key / multisig that queues ops
        address executor = vm.envOr("HIVE_TIMELOCK_EXECUTOR", address(0)); // 0 = permissionless execution
        address ensRegistrar = vm.envOr("ENS_REVERSE_REGISTRAR", address(0)); // optional ENS branding

        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        address[] memory executors = new address[](1);
        executors[0] = executor;

        vm.startBroadcast();
        timelock = new TimelockController(MIN_DELAY, proposers, executors, address(0)); // admin renounced
        vault = new HiveSeatVault(
            address(timelock),
            IERC721(SEAT_COLLECTION),
            IImdAgentAdapter(AGENT_ADAPTER),
            IEnsReverseRegistrar(ensRegistrar),
            rewardSink
        );
        vm.stopBroadcast();

        console2.log("TimelockController:", address(timelock));
        console2.log("  minDelay (s):", timelock.getMinDelay());
        console2.log("HiveSeatVault:", address(vault));
        console2.log("  owner:", vault.owner());

        // fail the deploy if the trust assumptions behind the whole design are not actually in place
        require(vault.owner() == address(timelock), "owner must be the timelock");
        require(timelock.getMinDelay() == MIN_DELAY, "delay must be 48h");
    }
}
