// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "openzeppelin-contracts/token/ERC20/ERC20.sol";
/// @notice Mock USDC token (6 decimals) used for testing.
contract MockUSDC is ERC20 {
    constructor() ERC20("Mock USDC", "mUSDC") {
        _mint(msg.sender, 1_000_000_000 * (10 ** 6));
    }
    function decimals() public pure returns (uint8) { return 6; }
}
