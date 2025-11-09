// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "openzeppelin-contracts/token/ERC20/IERC20.sol";
/// @notice Minimal mock for a Uniswap-compatible router used in tests.
contract MockUniversalRouter {
    function execute(bytes calldata, bytes[] calldata) external payable returns (bytes[] memory) {
        return new bytes[](0);
    }
}
