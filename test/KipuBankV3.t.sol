// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "../src/KipuBankV3.sol";
import "../src/MockUSDC.sol";
import "../src/MockERC20.sol";
import "../src/MockUniversalRouter.sol";
import "../src/MockPermit2.sol";

/// @notice Foundry tests for KipuBankV3 covering deposit, swap and withdraw flows.
contract KipuBankV3Test is Test {
    KipuBankV3 bank;
    MockUSDC usdc;
    MockERC20 token;
    MockUniversalRouter router;
    MockPermit2 permit2;
    address user = address(0xBEEF);

    function setUp() public {
        usdc = new MockUSDC();
        token = new MockERC20("TKN", "TKN", address(this), 1_000_000e18);
        router = new MockUniversalRouter();
        permit2 = new MockPermit2();

        bank = new KipuBankV3(
            address(usdc),
            address(router),
            address(permit2),
            address(0),
            1_000_000 * (10 ** 6),
            1000 * (10 ** 6)
        );

        usdc.transfer(user, 10000 * (10 ** 6));
        usdc.transfer(address(router), 50000 * (10 ** 6));
    }

    function test_depositUSDC_direct() public {
        uint256 amount = 100 * (10 ** 6);
        vm.prank(user);
        usdc.transfer(address(bank), amount);

        vm.prank(user);
        bank.depositArbitraryToken(address(usdc), amount, false, "", "", new bytes[](0));

        uint256 bal = bank.getUserUSDCBalance(user);
        assertEq(bal, amount);
    }

    function test_depositToken_and_swap() public {
        uint256 tAmount = 1000e18;
        token.transfer(user, tAmount);

        vm.prank(user);
        MockERC20(address(token)).approve(address(bank), tAmount);

        vm.prank(user);
        token.transfer(address(bank), tAmount);

        uint256 usdcToReceive = 500 * (10 ** 6);
        usdc.transfer(address(bank), usdcToReceive);

        vm.prank(user);
        bank.depositArbitraryToken(address(token), tAmount, false, "", "", new bytes[](0));

        uint256 bal = bank.getUserUSDCBalance(user);
        assertEq(bal, usdcToReceive);
    }

    function test_withdrawUSDC() public {
        uint256 amountUSDC = 200 * (10 ** 6);
        vm.prank(user);
        usdc.transfer(address(bank), amountUSDC);

        vm.prank(user);
        bank.depositArbitraryToken(address(usdc), amountUSDC, false, "", "", new bytes[](0));

        vm.prank(user);
        bank.withdrawUSDC(amountUSDC);

        uint256 bal = bank.getUserUSDCBalance(user);
        assertEq(bal, 0);
    }
}
