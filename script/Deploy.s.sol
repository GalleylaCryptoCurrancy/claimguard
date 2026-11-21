// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {ClaimGuardRegistry} from "../src/ClaimGuardRegistry.sol";

/// @notice Deploys ClaimGuardRegistry against the official Agent ID registry.
///
/// Usage (deployment is a separate, explicitly approved step — see PLAN.md):
///   AGENT_ID_REGISTRY=0x60B9262456dE011F7d15a54CdD8c48bAaa8B022F \
///   forge script script/Deploy.s.sol --rpc-url $BSC_RPC --broadcast \
///     --private-key $DEPLOYER_KEY
///
/// The deployer key is supplied via the environment at deploy time only and
/// is never stored in this repository.
contract Deploy is Script {
    function run() external returns (ClaimGuardRegistry registry) {
        address agentIdRegistry = vm.envOr(
            "AGENT_ID_REGISTRY",
            address(0x60B9262456dE011F7d15a54CdD8c48bAaa8B022F) // official Agent ID registry, BNB Chain
        );
        vm.startBroadcast();
        registry = new ClaimGuardRegistry(agentIdRegistry);
        vm.stopBroadcast();
    }
}
