// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title MockToken
 * @notice A simplified, non-standard implementation of the ERC20 interface for testing purposes.
 * @dev This contract includes cheat functions like `setBalance` and `setAllowance` and uses
 * simplified ERC20 logic (e.g., `transfer` always returns true) to facilitate unit testing.
 */
contract MockToken is IERC20 {
    /**
     * @notice Mapping to store user balances.
     * @dev Public mapping required by IERC20. Can be manipulated directly using `setBalance`.
     */
    mapping(address => uint256) public override balanceOf;
    
    /**
     * @notice Mapping to store allowances granted by token owners to spenders.
     * @dev Public mapping required by IERC20. Can be manipulated directly using `setAllowance`.
     */
    mapping(address => mapping(address => uint256)) public override allowance;

    /**
     * @notice Cheat function to directly set the balance of an account.
     * @dev Used exclusively in test environments to bypass standard minting or transfer logic.
     * @param account The address whose balance will be set.
     * @param amount The new balance amount.
     */
    function setBalance(address account, uint256 amount) external {
        balanceOf[account] = amount;
    }

    /**
     * @notice Cheat function to directly set the allowance granted by an owner to a spender.
     * @dev Used exclusively in test environments to bypass the standard `approve` transaction.
     * @param owner The address granting the allowance.
     * @param spender The address receiving the allowance.
     * @param amount The new allowance amount.
     */
    function setAllowance(
        address owner,
        address spender,
        uint256 amount
    ) external {
        allowance[owner][spender] = amount;
    }

    /**
     * @notice Mock implementation of the ERC20 `transfer` function.
     * @dev This function always returns true and does not update balances to simplify test logic.
     * It is marked `pure` to reflect its non-functional, mock nature.
     * @param to The recipient address.
     * @param amount The amount to transfer.
     * @return success Always returns true.
     */
    function transfer(address to, uint256 amount) external pure override returns (bool success) {
        return true;
    }

    /**
     * @notice Simplified implementation of the ERC20 `transferFrom` function.
     * @dev This mock function updates balances directly but does not check or reduce allowance, 
     * simplifying the logic for testing. It always returns true.
     * @param from The address of the token holder.
     * @param to The recipient address.
     * @param amount The amount to transfer.
     * @return success Always returns true.
     */
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external override returns (bool success) {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    /**
     * @notice Mock implementation of the ERC20 `approve` function.
     * @dev This function only updates the allowance mapping and always returns true.
     * @param spender The address to be allowed to spend.
     * @param amount The amount to be allowed.
     * @return success Always returns true.
     */
    function approve(
        address spender,
        uint256 amount
    ) external override returns (bool success) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    /**
     * @notice Mock implementation of the ERC20 `totalSupply` function.
     * @dev Returns 0 to simulate a token that is managed externally or has no initial supply.
     * @return The total supply, which is always 0.
     */
    function totalSupply() external pure override returns (uint256) {
        return 0;
    }

    /**
     * @notice Mock implementation of the token's decimal value.
     * @dev Returns 6, often used to simulate stablecoins like USDC.
     * @return The number of decimals, which is 6.
     */
    function decimals() external pure returns (uint8) {
        return 6;
    }

    /**
     * @notice Mock implementation of the token's name.
     * @dev Returns the fixed string "MockToken".
     * @return The token's name.
     */
    function name() external pure returns (string memory) {
        return "MockToken";
    }

    /**
     * @notice Mock implementation of the token's symbol.
     * @dev Returns the fixed string "MOCK".
     * @return The token's symbol.
     */
    function symbol() external pure returns (string memory) {
        return "MOCK";
    }
}