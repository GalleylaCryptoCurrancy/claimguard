// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal stand-in for the official Agent ID registry, used ONLY in
///         tests and local gas measurement: it implements just the
///         balanceOf surface ClaimGuardRegistry actually reads.
contract MockAgentIdRegistry {
    mapping(address => uint256) private _balances;

    function setBalance(address account, uint256 amount) external {
        _balances[account] = amount;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }
}
