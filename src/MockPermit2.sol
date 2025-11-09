// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "openzeppelin-contracts/token/ERC20/IERC20.sol";
/// @notice Simplified Permit2 mock that transfers tokens from `from` to `to`.
contract MockPermit2 {
    function permitTransferFrom(address from, address to, address token, uint256 amount, bytes calldata) external {
        bool ok = IERC20(token).transferFrom(from, to, amount);
        require(ok, "transfer failed");
    }
}
