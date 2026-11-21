// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ClaimGuardRegistry} from "../src/ClaimGuardRegistry.sol";
import {MockAgentIdRegistry} from "./mocks/MockAgentIdRegistry.sol";

contract ClaimGuardRegistryTest is Test {
    // Local mirrors of the contract's outcome/reason constants. They are
    // plain values (not contract calls) so vm.prank is never consumed by
    // argument evaluation; test_ConstantsMatchSpec pins them to the contract.
    uint8 internal constant OUTCOME_PASSED = 0;
    uint8 internal constant OUTCOME_REFUSED = 1;
    uint8 internal constant REASON_NONE = 0;
    uint8 internal constant REASON_CUSTOM_TOKEN = 2;
    uint8 internal constant REASON_PREVIEW_BLOCKED = 6;
    uint8 internal constant REASON_CODE_REQUIRED = 7;
    uint8 internal constant REASON_OTHER = 8;

    MockAgentIdRegistry internal idRegistry;
    ClaimGuardRegistry internal registry;

    address internal holder = address(0xA11CE); // holds an Agent ID
    address internal holder2 = address(0xB0B); // holds an Agent ID
    address internal stranger = address(0xDEAD); // holds no Agent ID

    bytes32 internal policy = keccak256("claimguard-policy-v1");
    bytes32 internal oppId = keccak256("agentid.im:hongbao:4");
    address internal target = 0xA39660B43c3F797d4bBEab8Df0e40D771565b8CE; // hongbao contract
    bytes32 internal detail = keccak256("gate-evaluation-detail");

    function setUp() public {
        idRegistry = new MockAgentIdRegistry();
        registry = new ClaimGuardRegistry(address(idRegistry));
        idRegistry.setBalance(holder, 1);
        idRegistry.setBalance(holder2, 1);
    }

    function test_ConstantsMatchSpec() public view {
        assertEq(registry.OUTCOME_PASSED(), OUTCOME_PASSED);
        assertEq(registry.OUTCOME_REFUSED(), OUTCOME_REFUSED);
        assertEq(registry.REASON_NONE(), REASON_NONE);
        assertEq(registry.REASON_CUSTOM_TOKEN(), REASON_CUSTOM_TOKEN);
        assertEq(registry.REASON_PREVIEW_BLOCKED(), REASON_PREVIEW_BLOCKED);
        assertEq(registry.REASON_CODE_REQUIRED(), REASON_CODE_REQUIRED);
        assertEq(registry.REASON_OTHER(), REASON_OTHER);
    }

    // ---------------------------------------------------------------
    // Registration gate
    // ---------------------------------------------------------------

    function test_RegisterAgent_SucceedsForHolder() public {
        vm.expectEmit(true, false, false, true);
        emit ClaimGuardRegistry.AgentRegistered(holder, policy, uint64(block.timestamp));
        vm.prank(holder);
        registry.registerAgent(policy);

        assertTrue(registry.isRegisteredAgent(holder));
        assertEq(registry.agentPolicy(holder), policy);
        assertEq(registry.agentCount(), 1);
        (bytes32 ph, uint64 ts) = registry.agentRecord(holder);
        assertEq(ph, policy);
        assertEq(ts, uint64(block.timestamp));
    }

    function test_RegisterAgent_RevertsForNonHolder() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(ClaimGuardRegistry.NotAgentIdHolder.selector, stranger));
        registry.registerAgent(policy);
        assertEq(registry.agentCount(), 0);
    }

    function test_RegisterAgent_RevertsAfterIdRevoked() public {
        // Balance drops to zero before registering -> gate must refuse.
        idRegistry.setBalance(holder2, 0);
        vm.prank(holder2);
        vm.expectRevert(abi.encodeWithSelector(ClaimGuardRegistry.NotAgentIdHolder.selector, holder2));
        registry.registerAgent(policy);
    }

    function test_RegisterAgent_RevertsOnDuplicate() public {
        vm.prank(holder);
        registry.registerAgent(policy);
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(ClaimGuardRegistry.AlreadyRegistered.selector, holder));
        registry.registerAgent(keccak256("other-policy"));
        assertEq(registry.agentCount(), 1);
    }

    function test_RegisterAgent_RevertsOnEmptyPolicy() public {
        vm.prank(holder);
        vm.expectRevert(ClaimGuardRegistry.EmptyPolicyHash.selector);
        registry.registerAgent(bytes32(0));
    }

    function test_Constructor_RevertsOnZeroRegistry() public {
        vm.expectRevert();
        new ClaimGuardRegistry(address(0));
    }

    // ---------------------------------------------------------------
    // Attestations
    // ---------------------------------------------------------------

    function test_AttestPass_SucceedsAndCounts() public {
        vm.prank(holder);
        registry.registerAgent(policy);

        vm.expectEmit(true, true, true, true);
        emit ClaimGuardRegistry.ClaimAttested(holder, oppId, target, OUTCOME_PASSED, REASON_NONE, detail);
        vm.prank(holder);
        registry.attestClaim(oppId, target, detail, OUTCOME_PASSED, REASON_NONE);

        assertEq(registry.attestationCount(), 1);
        assertEq(registry.passCount(), 1);
        assertEq(registry.refuseCount(), 0);
    }

    function test_AttestRefuse_SucceedsWithReasonAndCounts() public {
        vm.prank(holder);
        registry.registerAgent(policy);

        vm.expectEmit(true, true, true, true);
        emit ClaimGuardRegistry.ClaimAttested(holder, oppId, target, OUTCOME_REFUSED, REASON_CUSTOM_TOKEN, detail);
        vm.prank(holder);
        registry.attestClaim(oppId, target, detail, OUTCOME_REFUSED, REASON_CUSTOM_TOKEN);

        assertEq(registry.attestationCount(), 1);
        assertEq(registry.passCount(), 0);
        assertEq(registry.refuseCount(), 1);
    }

    function test_Attest_RevertsForUnregisteredHolder() public {
        // Holds an Agent ID but never registered -> cannot attest.
        vm.prank(holder2);
        vm.expectRevert(abi.encodeWithSelector(ClaimGuardRegistry.NotRegistered.selector, holder2));
        registry.attestClaim(oppId, target, detail, OUTCOME_PASSED, REASON_NONE);
    }

    function test_Attest_RevertsForStranger() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(ClaimGuardRegistry.NotRegistered.selector, stranger));
        registry.attestClaim(oppId, target, detail, OUTCOME_REFUSED, REASON_OTHER);
    }

    function test_Attest_RevertsOnInvalidOutcome() public {
        vm.prank(holder);
        registry.registerAgent(policy);
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(ClaimGuardRegistry.InvalidOutcome.selector, uint8(2)));
        registry.attestClaim(oppId, target, detail, 2, REASON_OTHER);
    }

    function test_Attest_RevertsOnPassWithReason() public {
        vm.prank(holder);
        registry.registerAgent(policy);
        vm.prank(holder);
        vm.expectRevert(ClaimGuardRegistry.ReasonNotAllowedForPass.selector);
        registry.attestClaim(oppId, target, detail, OUTCOME_PASSED, REASON_OTHER);
    }

    function test_Attest_RevertsOnRefusalWithoutReason() public {
        vm.prank(holder);
        registry.registerAgent(policy);
        vm.prank(holder);
        vm.expectRevert(ClaimGuardRegistry.ReasonRequiredForRefusal.selector);
        registry.attestClaim(oppId, target, detail, OUTCOME_REFUSED, REASON_NONE);
    }

    function test_MultipleAgentsAndAttestations() public {
        vm.prank(holder);
        registry.registerAgent(policy);
        vm.prank(holder2);
        registry.registerAgent(keccak256("policy-two"));
        assertEq(registry.agentCount(), 2);

        vm.prank(holder);
        registry.attestClaim(oppId, target, detail, OUTCOME_PASSED, REASON_NONE);
        vm.prank(holder2);
        registry.attestClaim(oppId, target, detail, OUTCOME_REFUSED, REASON_PREVIEW_BLOCKED);
        vm.prank(holder2);
        registry.attestClaim(oppId, target, detail, OUTCOME_REFUSED, REASON_CODE_REQUIRED);

        assertEq(registry.attestationCount(), 3);
        assertEq(registry.passCount(), 1);
        assertEq(registry.refuseCount(), 2);
    }

    // ---------------------------------------------------------------
    // Asset-free invariants
    // ---------------------------------------------------------------

    function test_ContractCannotReceiveEther() public {
        // No receive()/fallback and no payable entry points: a plain value
        // transfer must revert, keeping the contract asset-free.
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(registry).call{value: 1 ether}("");
        assertFalse(ok);
        assertEq(address(registry).balance, 0);
    }

    function test_ViewsForUnregisteredAreZero() public {
        assertFalse(registry.isRegisteredAgent(stranger));
        assertEq(registry.agentPolicy(stranger), bytes32(0));
        (bytes32 ph, uint64 ts) = registry.agentRecord(stranger);
        assertEq(ph, bytes32(0));
        assertEq(ts, 0);
    }
}
