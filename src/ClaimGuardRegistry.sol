// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal read interface for the official Agent ID registry
///         (SPACE ID Agent ID, ERC-721, non-transferable) on BNB Chain:
///         0x60B9262456dE011F7d15a54CdD8c48bAaa8B022F
interface IAgentIdRegistry {
    function balanceOf(address owner) external view returns (uint256);
}

/// @title ClaimGuardRegistry
/// @notice An Agent ID-gated, on-chain safety registry for autonomous agents.
///
///         Any holder of an Agent ID (checked live against the official Agent ID
///         registry) may register once and declare a hash of their off-chain
///         safety policy. Registered agents then write attestations recording
///         the outcome of every safety-gate evaluation their tooling performs
///         before attempting a value-bearing claim: PASSED (all gates green,
///         claim proceeded) or REFUSED (a gate stopped the claim), with a
///         machine-readable reason code. The result is a public, auditable
///         trail of what an agent claimed — and what its safety gates refused.
///
/// @dev    ASSET-FREE BY CONSTRUCTION: this contract holds no funds, has no
///         payable functions, performs no token transfers, requests no
///         approvals, and has NO owner and NO admin functions of any kind
///         (no mint, pause, freeze, withdraw, or upgrade path). The only
///         privileged input is the immutable Agent ID registry address set
///         once at deployment.
contract ClaimGuardRegistry {
    // ------------------------------------------------------------------
    // Outcome & reason codes (mirror the production gate vocabulary of the
    // ClaimGuard monitor; see README.md "Reason codes")
    // ------------------------------------------------------------------
    uint8 public constant OUTCOME_PASSED = 0;
    uint8 public constant OUTCOME_REFUSED = 1;

    uint8 public constant REASON_NONE = 0; // required for PASSED
    uint8 public constant REASON_HELPER_REFUSED = 1; // claim helper refused the opportunity
    uint8 public constant REASON_CUSTOM_TOKEN = 2; // non-standard token — never auto-claimed
    uint8 public constant REASON_UNEXPECTED_CALL_SET = 3; // helper produced != 1 call
    uint8 public constant REASON_PREVIEW_TARGET_MISMATCH = 4; // preview target != expected contract
    uint8 public constant REASON_PREVIEW_VALUE_NONZERO = 5; // preview carried a non-zero value
    uint8 public constant REASON_PREVIEW_BLOCKED = 6; // preview error / risk / execution failure
    uint8 public constant REASON_CODE_REQUIRED = 7; // held for a human-supplied code/passphrase
    uint8 public constant REASON_OTHER = 8; // any other fail-closed stop

    /// @notice The official Agent ID registry this contract gates on.
    IAgentIdRegistry public immutable agentIdRegistry;

    struct AgentRecord {
        bytes32 policyHash; // hash of the agent's off-chain safety policy document
        uint64 registeredAt; // block timestamp of registration
    }

    mapping(address => AgentRecord) private _agents;

    /// @notice Total registered agents.
    uint256 public agentCount;
    /// @notice Total attestations written.
    uint256 public attestationCount;
    /// @notice Total PASSED attestations.
    uint256 public passCount;
    /// @notice Total REFUSED attestations.
    uint256 public refuseCount;

    event AgentRegistered(address indexed agent, bytes32 policyHash, uint64 registeredAt);
    event ClaimAttested(
        address indexed agent,
        bytes32 indexed opportunityId,
        address indexed target,
        uint8 outcome,
        uint8 reason,
        bytes32 detailHash
    );

    error NotAgentIdHolder(address account);
    error AlreadyRegistered(address account);
    error EmptyPolicyHash();
    error NotRegistered(address account);
    error InvalidOutcome(uint8 outcome);
    error ReasonRequiredForRefusal();
    error ReasonNotAllowedForPass();

    /// @param agentIdRegistry_ Address of the official Agent ID registry
    ///        (BNB Chain mainnet: 0x60B9262456dE011F7d15a54CdD8c48bAaa8B022F).
    constructor(address agentIdRegistry_) {
        require(agentIdRegistry_ != address(0), "registry is zero address");
        agentIdRegistry = IAgentIdRegistry(agentIdRegistry_);
    }

    /// @notice Register the caller as a ClaimGuard agent and declare the hash
    ///         of its safety policy. Caller must hold an Agent ID.
    /// @param policyHash keccak256 (or SHA-256, hex-encoded) of the agent's
    ///        published safety-policy document. Must be non-zero.
    function registerAgent(bytes32 policyHash) external {
        if (agentIdRegistry.balanceOf(msg.sender) == 0) {
            revert NotAgentIdHolder(msg.sender);
        }
        if (_agents[msg.sender].registeredAt != 0) {
            revert AlreadyRegistered(msg.sender);
        }
        if (policyHash == bytes32(0)) revert EmptyPolicyHash();

        uint64 ts = uint64(block.timestamp);
        _agents[msg.sender] = AgentRecord({policyHash: policyHash, registeredAt: ts});
        agentCount += 1;
        emit AgentRegistered(msg.sender, policyHash, ts);
    }

    /// @notice Record the outcome of one safety-gate evaluation.
    /// @param opportunityId Opaque id of the evaluated opportunity
    ///        (e.g. keccak256 of a namespaced packet/opportunity identifier).
    /// @param target The contract the claim would have interacted with.
    /// @param detailHash Hash of the off-chain gate-evaluation detail record.
    /// @param outcome OUTCOME_PASSED (0) or OUTCOME_REFUSED (1).
    /// @param reason REASON_NONE (0) for a pass; a non-zero REASON_* code for
    ///        a refusal.
    function attestClaim(
        bytes32 opportunityId,
        address target,
        bytes32 detailHash,
        uint8 outcome,
        uint8 reason
    ) external {
        if (_agents[msg.sender].registeredAt == 0) {
            revert NotRegistered(msg.sender);
        }
        if (outcome != OUTCOME_PASSED && outcome != OUTCOME_REFUSED) {
            revert InvalidOutcome(outcome);
        }
        if (outcome == OUTCOME_PASSED && reason != REASON_NONE) {
            revert ReasonNotAllowedForPass();
        }
        if (outcome == OUTCOME_REFUSED && reason == REASON_NONE) {
            revert ReasonRequiredForRefusal();
        }

        attestationCount += 1;
        if (outcome == OUTCOME_PASSED) {
            passCount += 1;
        } else {
            refuseCount += 1;
        }
        emit ClaimAttested(msg.sender, opportunityId, target, outcome, reason, detailHash);
    }

    /// @notice True if `account` is a registered ClaimGuard agent.
    function isRegisteredAgent(address account) external view returns (bool) {
        return _agents[account].registeredAt != 0;
    }

    /// @notice The declared safety-policy hash of a registered agent
    ///         (zero if the address is not registered).
    function agentPolicy(address account) external view returns (bytes32) {
        return _agents[account].policyHash;
    }

    /// @notice Full registration record of an agent
    ///         (policyHash zero and registeredAt 0 if not registered).
    function agentRecord(address account) external view returns (bytes32 policyHash, uint64 registeredAt) {
        AgentRecord memory r = _agents[account];
        return (r.policyHash, r.registeredAt);
    }
}
