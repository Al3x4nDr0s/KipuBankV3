// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {Test} from "forge-std/Test.sol";
import {MockToken} from "../src/MockToken.sol";

/**
 * @title MockTokenTest
 * @author Lletsica Villarroel
 * @notice Test suite for the MockToken contract, verifying its core ERC20 functionality 
 * and cheat code features (setBalance, setAllowance).
 * @dev This test focuses on ensuring the mock behavior is correctly implemented for unit testing purposes.
 */
contract MockTokenTest is Test {
    MockToken token;
    address alice = address(0x1);
    address bob = address(0x2);

    /**
     * @notice Sets up the testing environment.
     * @dev Deploys a new instance of the MockToken contract before each test function.
     */
    function setUp() public {
        token = new MockToken();
    }

    /**
     * @notice Tests the cheat code ability to set a user's token balance.
     * @dev Verifies that `setBalance` correctly updates the balance mapping.
     */
    function testSetBalance() public {
        // Why test this: To confirm the primary cheat function for token setup works.
        token.setBalance(alice, 1000);
        assertEq(token.balanceOf(alice), 1000);
    }

    /**
     * @notice Tests the cheat code ability to set a spender's allowance.
     * @dev Verifies that `setAllowance` correctly updates the allowance mapping.
     */
    function testSetAllowance() public {
        // Why test this: To confirm the cheat function for setting allowance works without requiring an approval transaction.
        token.setAllowance(alice, bob, 500);
        assertEq(token.allowance(alice, bob), 500);
    }

    /**
     * @notice Tests that the transfer function always returns true (mock behavior).
     * @dev Confirms that the transfer function doesn't revert and is simplified for testing.
     */
    function testTransferAlwaysTrue() public view {
        // Why test this: Mock tokens often bypass complex checks and simply return true to simplify testing external calls.
        bool success = token.transfer(bob, 100);
        assertTrue(success);
    }

    /**
     * @notice Tests the transferFrom function's ability to update balances and consume allowance.
     * @dev Verifies that transferFrom updates both sender's and recipient's balances correctly.
     */
    function testTransferFromUpdatesBalances() public {
        // Why test this: To ensure that even though it's a mock, it simulates the core state change logic (balances decrease/increase).
        token.setBalance(alice, 1000);
        token.setAllowance(alice, address(this), 1000);
        bool success = token.transferFrom(alice, bob, 200);
        assertTrue(success);
        assertEq(token.balanceOf(alice), 800);
        assertEq(token.balanceOf(bob), 200);
    }

    /**
     * @notice Tests the standard ERC20 approve function.
     * @dev Verifies that `approve` sets the allowance correctly for the caller (`address(this)` in the test context).
     */
    function testApproveSetsAllowance() public {
        // Why test this: To confirm the standard ERC20 interface works as expected when called by the test contract itself.
        bool success = token.approve(bob, 300);
        assertTrue(success);
        assertEq(token.allowance(address(this), bob), 300);
    }

    /**
     * @notice Tests that the total supply is initially zero.
     * @dev Confirms the mock token does not start with any minted tokens.
     */
    function testTotalSupplyIsZero() public view {
        // Why test this: To ensure the mock token starts from a clean state.
        assertEq(token.totalSupply(), 0);
    }

    /**
     * @notice Tests that the decimals function returns 6.
     * @dev Confirms the mock token simulates USDC-like behavior (6 decimals).
     */
    function testDecimalsIsSix() public view {
        // Why test this: Many banking contracts rely on 6 decimals (like USDC), so the mock confirms this expected behavior.
        assertEq(token.decimals(), 6);
    }

    /**
     * @notice Tests that the token name is correct.
     */
    function testNameIsMockToken() public view {
        // Why test this: Basic ERC20 metadata check.
        assertEq(token.name(), "MockToken");
    }

    /**
     * @notice Tests that the token symbol is correct.
     */
    function testSymbolIsMOCK() public view {
        // Why test this: Basic ERC20 metadata check.
        assertEq(token.symbol(), "MOCK");
    }
}