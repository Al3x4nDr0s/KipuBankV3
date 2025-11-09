// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {KipuBankV3} from "../src/KipuBankV3.sol";
import {MockToken} from "../src/MockToken.sol";
import {DeployKipuBankV3} from "../script/DeployKipuBankV3.s.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IUniswapV2Router02} from "v2-periphery/interfaces/IUniswapV2Router02.sol";

/**
 * @title KipuBankV3Test
 * @author @lletsica (Test Author)
 * @notice Test suite for the KipuBankV3 contract using the Forge testing framework.
 * @dev This contract uses a Sepolia fork to simulate on-chain interactions with live addresses for USDC,
 * Chainlink Price Feed, and Uniswap V2 Router.
 */
contract KipuBankV3Test is Test {
    KipuBankV3 public kipu;
    DeployKipuBankV3 public deployer;
    address public immutable WETH = address(0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9);
    address usdc = address(0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238);
    address priceFeed = address(0x694AA1769357215DE4FAC081bf1f309aDC325306);
    address router = address(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
    address admin = address(this);
    address user = address(0x123);
    address user2 = address(0x456);
    address userAdmin = address(0x789);

    /**
     * @notice Sets up the initial state for each test.
     * @dev Forks the blockchain from the RPC defined in the environment variables, deploys the KipuBankV3
     * contract, sets up initial roles (Admin, Depositor, Withdrawer), and simulates an initial USDC deposit.
     */
    function setUp() public {
        // Fork from the RPC defined in .env
        vm.createSelectFork(vm.envString("RPC"));
        deployer = new DeployKipuBankV3();
        // Deploy the contract
        kipu = new KipuBankV3(
            100 ether, // _bankCap = 100 ether
            5 ether, // _maxWithdrawalPerTx = 5 ether
            usdc,
            priceFeed,
            6, // USDC token decimals
            router
        );

        // Configure permissions
        kipu.addToWhitelist(user);
        kipu.addToWhitelist(user2);
        kipu.grantRole(kipu.DEPOSITOR_ROLE(), user);
        kipu.grantRole(kipu.WITHDRAWER_ROLE(), user);
        kipu.grantRole(kipu.DEFAULT_ADMIN_ROLE(), userAdmin);

        // Simulate an initial USDC deposit by 'user'
        deal(usdc, user, 1_000 * 10 ** 6);
        // Assign 1000 USDC (6 decimals) to the user
        vm.startPrank(user);
        IERC20(usdc).approve(address(kipu), 100 * 10 ** 6); // Approve 100 USDC
        kipu.depositUsdc(100 * 10 ** 6);
        // Deposit 100 USDC
        vm.stopPrank();
    }

    /**
     * @notice Tests that the `getLatestPrice` function returns a price greater than zero.
     */
    function testGetLatestPrice() public view {
        console.log("testGetLatestPrice");
        int256 price = kipu.getLatestPrice();
        assert(price > 0);
    }

    /**
     * @notice Tests that depositing a zero amount of ETH reverts with `DepositAmountZero`.
     */
    function testDepositEthZeroReverts() public {
        vm.startPrank(user);
        vm.expectRevert(KipuBankV3.DepositAmountZero.selector);
        kipu.depositEth{value: 0}();
    }

    /**
     * @notice Tests that depositing a zero amount of USDC reverts with `DepositAmountZero`.
     */
    function testDepositUsdcZeroReverts() public {
        vm.startPrank(user);
        IERC20(usdc).approve(address(kipu), 1e18);
        vm.expectRevert(KipuBankV3.DepositAmountZero.selector);
        kipu.depositUsdc(0);
        vm.stopPrank();
    }

    /**
     * @notice Tests the successful addition and removal of an address from the whitelist.
     */
    function testAddRemoveWhitelist() public {
        kipu.addToWhitelist(address(0x999));
        assertTrue(kipu.whitelist(address(0x999)));
        kipu.removeFromWhitelist(address(0x999));
        assertFalse(kipu.whitelist(address(0x999)));
    }

    /**
     * @notice Tests that direct ETH transfers via `receive()` and calls to non-existent functions via `fallback()` revert.
     */
    function testReceiveFallbackReverts() public {
        console.log("testReceiveFallbackReverts");
        (bool ok1, ) = address(kipu).call{value: 1 ether}("");
        assertFalse(ok1);
        (bool ok2, ) = address(kipu).call(
            abi.encodeWithSignature("nonexistent()")
        );
        assertFalse(ok2);
    }

    /**
     * @notice Tests the successful deposit of ETH, checking user balance, event emission, and deposit counter.
     */
    function testDepositEthSuccess() public {
        uint256 depositAmount = 1 ether;
        // Simulate sending ETH from the user
        vm.deal(user, depositAmount);
        // Assign ETH to the user
        vm.startPrank(user);
        // Capture event
        vm.expectEmit(true, true, false, true);
        emit KipuBankV3.DepositEth(user, depositAmount);
        // Execute the deposit
        kipu.depositEth{value: depositAmount}();
        // Verify internal balance
        uint256 userBalance = kipu.userEthBalances(user);
        assertEq(
            userBalance,
            depositAmount,
            "User's ETH balance must match the deposit amount"
        );
        // Verify deposit counter
        assertEq(
            kipu.depositCounter(),
            2,
            "The deposit counter must be incremented"
        );
        vm.stopPrank();
    }

    /**
     * @notice Tests the successful withdrawal of ETH, checking the contract's internal balance, the user's external balance, event emission, and withdrawal counter.
     */
    function testWithdrawEthSuccess() public {
        uint256 depositAmount = 2 ether;
        uint256 withdrawAmount = 1 ether;

        // Assign ETH to the user and simulate a prior deposit
        vm.deal(user, depositAmount);
        vm.startPrank(user);
        kipu.depositEth{value: depositAmount}();
        vm.stopPrank();

        // Capture user's balance before withdrawal
        uint256 userBalanceBefore = user.balance;
        // Execute withdrawal
        vm.startPrank(user);
        vm.expectEmit(true, true, false, true);
        emit KipuBankV3.Withdrawal(user, address(0), withdrawAmount);
        kipu.withdrawEth(withdrawAmount);
        vm.stopPrank();

        // Verify the contract's internal balance
        uint256 remainingBalance = kipu.userEthBalances(user);
        assertEq(
            remainingBalance,
            depositAmount - withdrawAmount,
            "The internal ETH balance must decrease"
        );
        // Verify the user received the ETH
        uint256 userBalanceAfter = user.balance;
        assertEq(
            userBalanceAfter,
            userBalanceBefore + withdrawAmount,
            "The user must receive the withdrawn ETH"
        );
        // Verify withdrawal counter
        assertEq(
            kipu.withdrawalCounter(),
            1,
            "The withdrawal counter must be incremented"
        );
    }

    /**
     * @notice Tests the successful withdrawal of USDC, checking the contract's internal USDC balance.
     */
    function testWithdrawUsdcSuccess() public {
        uint256 depositAmount = 100 * 10 ** 6;
        uint256 withdrawAmount = 40 * 10 ** 6;

        // Assign USDC and deposit
        deal(usdc, user, depositAmount);
        vm.startPrank(user);
        IERC20(usdc).approve(address(kipu), depositAmount);
        kipu.depositUsdc(depositAmount);
        vm.stopPrank();

        // Capture internal balance before withdrawal
        uint256 beforeBalance = kipu.userUsdcBalances(user);
        // Execute withdrawal
        vm.startPrank(user);
        kipu.withdrawUsdc(withdrawAmount);
        vm.stopPrank();
        // Verify that the withdrawal was reflected correctly
        uint256 afterBalance = kipu.userUsdcBalances(user);
        assertEq(
            afterBalance,
            beforeBalance - withdrawAmount,
            "The withdrawal must correctly decrease the internal balance"
        );
    }

    /**
     * @notice Tests that a `depositTokenToUsdc` swap reverts with `NoUsdcReceived` if the swap yields zero USDC.
     * @dev This test mocks the Uniswap V2 Router call to simulate the failure condition.
     */
    function testDepositTokenToUsdcNoUsdcReceivedReverts() public {
        MockToken mock = new MockToken();
        address tokenIn = address(mock);

        address[] memory path = new address[](3);
        path[0] = tokenIn;
        path[1] = WETH;
        // WETH address defined in setUp
        path[2] = usdc;

        uint256 depositAmount = 1e6;
        uint256 minAmountOut = 100 * 10 ** 6; // Expect at least 100 USDC

        // KEY CORRECTION: Use 'deal' to assign tokens to the user
        deal(tokenIn, user, depositAmount);
        // The user has the necessary tokenIn

        // 1. Set the initial USDC balance in the KipuBank contract
        uint256 usdcBefore = 1_000 * 10 ** 6;
        deal(usdc, address(kipu), usdcBefore);

        vm.startPrank(user);
        IERC20(tokenIn).approve(address(kipu), depositAmount);

        // 2. Mock the swap: Simulate the call to the router
        vm.mockCall(
            address(kipu.UNISWAP_ROUTER()),
            abi.encodeWithSelector(
                IUniswapV2Router02
                    .swapExactTokensForTokensSupportingFeeOnTransferTokens
                    .selector,
                depositAmount,
                minAmountOut,
                path,
                address(kipu),
                block.timestamp
            ),
            abi.encode()
        );
        // 3. Simulate balance after swap (less than the minimum expected)
        uint256 usdcReceived = 0; // Simulate zero USDC received
        deal(usdc, address(kipu), usdcBefore + usdcReceived);
        vm.expectRevert(KipuBankV3.NoUsdcReceived.selector);
        kipu.depositTokenToUsdc(tokenIn, depositAmount, minAmountOut, path);

        vm.stopPrank();
    }

    /**
     * @notice Tests that the `ethWeiToUsd` conversion function returns the expected USD value.
     * @dev Mocks the Chainlink price feed to return a fixed price for calculation verification.
     */
    function testEthWeiToUsdReturnsExpectedValue() public {
        // Simulate a price of 2000 USD per ETH (with 8 decimals, like Chainlink)
        int256 mockPrice = 2000 * 10 ** 8;
        uint80 roundId = 1;
        uint256 updatedAt = block.timestamp;
        bytes memory response = abi.encode(roundId, mockPrice, 0, updatedAt, 0);
        // Mock the price feed
        vm.mockCall(
            address(kipu.PRICE_FEED()),
            abi.encodeWithSelector(kipu.PRICE_FEED().latestRoundData.selector),
            response
        );
        // Call the function with 1 ether
        uint256 ethAmount = 1 ether;
        uint256 usd = kipu.ethWeiToUsd(ethAmount);

        // forge-lint: disable-next-line(unsafe-typecast)
        uint256 expectedUsd = (ethAmount * uint256(mockPrice)) / 1e26;
        assertEq(
            usd,
            expectedUsd,
            "The ETH to USD conversion must be correct"
        );
    }

    /**
     * @notice Tests the ability of the admin to pause and unpause the contract.
     */
    function testPauseAndUnpause() public {
        // Verify that the contract is active initially
        assertFalse(
            kipu.paused(),
            "The contract should not be paused initially"
        );
        // Pause the contract
        kipu.pause();
        assertTrue(kipu.paused(), "The contract should be paused");
        // Unpause the contract
        kipu.unpause();
        assertFalse(
            kipu.paused(),
            "The contract should be active again"
        );
    }

    /**
     * @notice Tests that a deposit of USDC reverts when the contract is paused.
     */
    function testDepositUsdcFailsWhenPaused() public {
        uint256 depositAmount = 50 * 10 ** 6;
        // Assign USDC to the user
        deal(usdc, user, depositAmount);
        vm.startPrank(user);
        IERC20(usdc).approve(address(kipu), depositAmount);
        vm.stopPrank();
        // Pause the contract as admin
        kipu.pause();
        assertTrue(kipu.paused(), "The contract must be paused");
        // Attempt to deposit USDC and expect revert
        vm.startPrank(user);
        vm.expectRevert("Pausable: paused");
        kipu.depositUsdc(depositAmount);
        vm.stopPrank();
    }

    /**
     * @notice Tests that an address with `DEFAULT_ADMIN_ROLE` can pause the contract.
     */
    function testUserAdminCanPauseContract() public {
        // Assign admin role (already done in setUp, but explicitly included for test clarity)
        kipu.grantRole(kipu.DEFAULT_ADMIN_ROLE(), userAdmin);
        // Simulate action as userAdmin
        vm.startPrank(userAdmin);
        kipu.pause();
        assertTrue(
            kipu.paused(),
            "The contract must be paused by userAdmin"
        );
        vm.stopPrank();
    }

    /**
     * @notice Tests that an admin can successfully perform an emergency withdrawal of USDC.
     */
    function testUserAdminCanEmergencyWithdrawUsdc() public {
        // Assign admin role (already done in setUp, but explicitly included for test clarity)
        kipu.grantRole(kipu.DEFAULT_ADMIN_ROLE(), userAdmin);
        // Ensure the contract has USDC
        uint256 depositAmount = 100 * 10 ** 6;
        deal(usdc, user, depositAmount);
        vm.startPrank(user);
        IERC20(usdc).approve(address(kipu), depositAmount);
        kipu.depositUsdc(depositAmount);
        vm.stopPrank();

        // Capture userAdmin's balance before withdrawal
        uint256 balanceBefore = IERC20(usdc).balanceOf(userAdmin);
        // Execute emergency withdrawal
        vm.startPrank(userAdmin);
        kipu.emergencyWithdraw(usdc, depositAmount);
        vm.stopPrank();
        // Verify that userAdmin received the funds
        uint256 balanceAfter = IERC20(usdc).balanceOf(userAdmin);
        assertEq(
            balanceAfter - balanceBefore,
            depositAmount,
            "userAdmin must receive the withdrawn USDC"
        );
    }

    /**
     * @notice Tests that `depositTokenToUsdc` reverts with `InsufficientAllowance` if the user has not approved the bank contract to spend the input token.
     */
    function testDepositTokenToUsdcFailsWithoutApproval() public {
        address linkToken = address(0x779877A7B0D9E8603169DdbD7836e478b4624789);
        address linkHolder = address(
            0x268b9DbE1Ff41904310C1B83cDF1Be7ee6D3e009
        );
        uint256 linkAmount = 10 * 10 ** 18;
        uint256 minUsdcOut = 1 * 10 ** 6;
        // Assign permissions and whitelist
        kipu.addToWhitelist(linkHolder);
        kipu.grantRole(kipu.DEPOSITOR_ROLE(), linkHolder);
        // Impersonate the admin
        vm.startPrank(admin);
        kipu.approveRouterForToken(linkToken);
        // Impersonate the holder
        vm.startPrank(linkHolder);
        // Assign LINK to the holder
        deal(linkToken, linkHolder, linkAmount);
        // The contract is NOT approved to spend LINK

        // Define the swap path: LINK → WETH → USDC
        address[] memory path = new address[](3);
        path[0] = linkToken;
        path[1] = WETH;
        path[2] = usdc;

        // Expect revert due to lack of approval
        vm.expectRevert(KipuBankV3.InsufficientAllowance.selector);
        kipu.depositTokenToUsdc(linkToken, linkAmount, minUsdcOut, path);

        vm.stopPrank();
    }

    /**
     * @notice Tests the allowance logic for `depositTokenToUsdc` by ensuring the user approves the bank and the bank approves the router.
     */
    function testLinkApprovalForRouter() public {
        address linkToken = address(0x779877A7B0D9E8603169DdbD7836e478b4624789);
        address linkHolder = address(
            0x268b9DbE1Ff41904310C1B83cDF1Be7ee6D3e009
        );
        uint256 linkAmount = 10 * 10 ** 18;

        // Assign permissions and whitelist
        kipu.addToWhitelist(linkHolder);
        kipu.grantRole(kipu.DEPOSITOR_ROLE(), linkHolder);

        // Impersonate the holder
        vm.startPrank(linkHolder);
        // Assign LINK to the holder
        deal(linkToken, linkHolder, linkAmount);
        // Approve the contract to spend LINK
        IERC20(linkToken).approve(address(kipu), linkAmount);
        // Verify that the contract has approval to spend the user's LINK
        uint256 allowanceToKipu = IERC20(linkToken).allowance(
            linkHolder,
            address(kipu)
        );
        assertEq(
            allowanceToKipu,
            linkAmount,
            "KipuBankV3 must have approval to spend the user's LINK"
        );
        // Simulate the contract approving the router (this normally happens inside depositTokenToUsdc)
        vm.stopPrank();
        vm.startPrank(address(kipu)); // Simulate the contract approving the router
        IERC20(linkToken).approve(router, type(uint256).max);
        // Verify that the router has maximum approval to spend LINK from the contract
        uint256 allowanceToRouter = IERC20(linkToken).allowance(
            address(kipu),
            router
        );
        assertEq(
            allowanceToRouter,
            type(uint256).max,
            "The router must have maximum approval to spend LINK from the contract"
        );
    }

    /**
     * @notice Tests the successful emergency withdrawal of ETH by an authorized admin.
     */
    function testEmergencyWithdrawEthSuccess() public {
        address _admin = user;
        uint256 _amount = 1 ether;

        // Simulate that the contract holds ETH
        vm.deal(address(kipu), _amount);
        uint256 initialBalance = _admin.balance;

        // Ensure the caller has the admin role
        kipu.grantRole(kipu.DEFAULT_ADMIN_ROLE(), _admin);
        // Execute as admin
        vm.startPrank(_admin);
        kipu.emergencyWithdraw(address(0), _amount);
        // Verify that ETH was transferred correctly
        assertEq(
            _admin.balance,
            initialBalance + _amount,
            "The admin must receive the ETH"
        );
        assertEq(address(kipu).balance, 0, "The contract balance should be zero");
    }

    /**
     * @notice Tests that an emergency withdrawal of ETH reverts if the receiver (admin) is a contract that rejects ETH.
     */
    function testEmergencyWithdrawEthFails() public {
        address _receiver = address(0xe839305F80114568D524eb3048bEFA78dcc06Aa0);
        // sepolia RejectEth contract
        uint256 _amount = 1 ether;
        // Simulate that the contract holds ETH
        vm.deal(address(kipu), _amount);
        // Ensure the caller has the admin role
        kipu.grantRole(kipu.DEFAULT_ADMIN_ROLE(), address(_receiver));
        // Execute as the contract that rejects ETH
        vm.startPrank(address(_receiver));
        vm.expectRevert(KipuBankV3.EthTransferFailed.selector);
        kipu.emergencyWithdraw(address(0), _amount);
    }

    /**
     * @notice Tests that withdrawing a zero amount of ETH reverts with `WithdrawalAmountZero`.
     */
    function testWithdrawEthZeroReverts() public {
        vm.startPrank(user);
        vm.expectRevert(KipuBankV3.WithdrawalAmountZero.selector);
        kipu.withdrawEth(0);
    }

    /**
     * @notice Tests that withdrawing a zero amount of USDC reverts with `WithdrawalAmountZero`.
     */
    function testWithdrawUsdcZeroReverts() public {
        vm.startPrank(user);
        vm.expectRevert(KipuBankV3.WithdrawalAmountZero.selector);
        kipu.withdrawUsdc(0);
    }

    /**
     * @notice Tests that depositing ETH exceeding the `BANK_CAP` reverts with `DepositExceedsBankCap`.
     */
    function testDepositEthExceedsBankCapReverts() public {
        vm.deal(user, 200 ether);
        vm.startPrank(user);
        vm.expectRevert(KipuBankV3.DepositExceedsBankCap.selector);
        kipu.depositEth{value: 200 ether}();
        vm.stopPrank();
    }

    /**
     * @notice Tests that withdrawing USDC without a sufficient balance reverts with `InsufficientUserBalance`.
     */
    function testWithdrawUsdcInsufficientBalanceReverts() public {
        vm.startPrank(user);
        vm.expectRevert(KipuBankV3.InsufficientUserBalance.selector);
        // Attempt to withdraw an amount significantly larger than the initial deposit (100 USDC in setUp)
        kipu.withdrawUsdc(999_999 * 10 ** 6);
    }

    /**
     * @notice Tests that withdrawing ETH exceeding the `MAX_WITHD_PER_TX` limit reverts with `WithdrawalExceedsLimit`.
     */
    function testWithdrawEthExceedsLimitReverts() public {
        vm.deal(user, 10 ether);
        vm.startPrank(user);
        kipu.depositEth{value: 10 ether}();
        vm.expectRevert(
            abi.encodeWithSelector(
                KipuBankV3.WithdrawalExceedsLimit.selector,
                5 ether
            )
        );
        kipu.withdrawEth(6 ether);
        vm.stopPrank();
    }

    /**
     * @notice Tests that depositing ETH from a non-whitelisted address reverts with `NotWhitelisted`.
     */
    function testDepositEthNotWhitelistedReverts() public {
        address unlisted = address(0x999);
        vm.deal(unlisted, 1 ether);
        vm.startPrank(unlisted);
        vm.expectRevert(
            abi.encodeWithSelector(KipuBankV3.NotWhitelisted.selector, unlisted)
        );
        kipu.depositEth{value: 1 ether}();
    }

    /**
     * @notice Tests that calling `depositTokenToUsdc` with `_tokenIn` as address(0) reverts with `InvalidTokenAddress`.
     */
    function testDepositTokenToUsdcInvalidTokenAddressReverts() public {
        address[] memory path = new address[](2);
        path[0] = address(0x123);
        path[1] = usdc;

        vm.startPrank(user);
        vm.expectRevert(KipuBankV3.InvalidTokenAddress.selector);
        kipu.depositTokenToUsdc(address(0), 1e18, 1e6, path);
    }

    /**
     * @notice Tests that calling `depositTokenToUsdc` with an invalid swap path (too short or not ending in USDC) reverts with `InvalidTokenAddress`.
     */
    function testDepositTokenToUsdcInvalidPathReverts() public {
        address tokenIn = address(new MockToken());
        uint256 amountIn = 1e6;

        // Case 1: Path is too short (< 2)
        address[] memory pathShort = new address[](1);
        pathShort[0] = tokenIn;

        vm.startPrank(user);
        vm.expectRevert(KipuBankV3.InvalidTokenAddress.selector);
        kipu.depositTokenToUsdc(tokenIn, amountIn, 1, pathShort);

        // Case 2: Path does not end in USDC
        address[] memory pathEndsInWeth = new address[](2);
        pathEndsInWeth[0] = tokenIn;
        pathEndsInWeth[1] = WETH;

        vm.expectRevert(KipuBankV3.InvalidTokenAddress.selector);
        kipu.depositTokenToUsdc(tokenIn, amountIn, 1, pathEndsInWeth);
        vm.stopPrank();
    }

    /**
     * @notice Tests that an arbitrary external call to a non-existent function is handled by the `fallback()` function and reverts with `UnsupportedFunction`.
     */
    function testFallbackRevertsWithUnsupportedFunction() public {
        vm.startPrank(user);
        (bool success, bytes memory data) = address(kipu).call(
            abi.encodeWithSignature("nonexistentFunction()")
        );
        assertFalse(success, "The call must fail");

        // Verify that the revert was due to UnsupportedFunction
        bytes4 expectedSelector = KipuBankV3.UnsupportedFunction.selector;
        bytes4 actualSelector;
        assembly {
            actualSelector := mload(add(data, 0x20))
        }
        assertEq(
            actualSelector,
            expectedSelector,
            "The error must be UnsupportedFunction"
        );
    }

    /**
     * @notice Tests that a direct ETH transfer to the contract's `receive()` function reverts with `UseDepositEth`.
     */
    function testReceiveRevertsWithUseDepositEth() public {
        vm.deal(user, 1 ether);
        vm.startPrank(user);
        // Expect revert with the custom error
        vm.expectRevert(
            abi.encodeWithSelector(KipuBankV3.UseDepositEth.selector)
        );
        payable(address(kipu)).transfer(1 ether);
    }

    /**
     * @notice Tests that calling `depositTokenToUsdc` reverts with `InsufficientAllowance` if the user has not approved the bank to spend the tokens.
     */
    function testDepositTokenToUsdcInsufficientAllowanceReverts() public {
        address token = usdc;
        address[] memory path = new address[](2);
        path[0] = token;
        path[1] = usdc;

        deal(token, user, 1e6);
        vm.startPrank(user);
        vm.expectRevert(KipuBankV3.InsufficientAllowance.selector);
        kipu.depositTokenToUsdc(token, 1e6, 1e6, path);
    }

    /**
     * @notice Tests that the `getLatestPrice` function reverts with `InvalidPrice` if the Chainlink price feed returns an invalid price (e.g., zero).
     */
    function testGetLatestPriceInvalidReverts() public {
        bytes memory response = abi.encode(0, int256(0), 0, block.timestamp, 0);
        vm.mockCall(
            address(kipu.PRICE_FEED()),
            abi.encodeWithSelector(kipu.PRICE_FEED().latestRoundData.selector),
            response
        );
        vm.expectRevert(
            abi.encodeWithSelector(KipuBankV3.InvalidPrice.selector, int256(0))
        );
        kipu.getLatestPrice();
    }

    /**
     * @notice Tests the deployment and initialization of the `KipuBankV3` contract, verifying immutable parameters.
     */
    function testDeployment() public {
        kipu = deployer.run();
        // Verify deployment was successful
        assertTrue(address(kipu) != address(0), "KipuBank deployment failed");
        // Test initial parameters
        assertEq(
            address(kipu.USDC_TOKEN()),
            address(0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238)
        );
        assertEq(
            address(kipu.PRICE_FEED()),
            address(0x694AA1769357215DE4FAC081bf1f309aDC325306)
        );
        assertEq(
            address(kipu.UNISWAP_ROUTER()),
            address(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D)
        );
        assertEq(kipu.USDC_DECIMALS(), 6);
    }

    /**
     * @notice Tests that the constructor reverts with `InvalidTokenAddress` if the USDC address is `address(0)`.
     */
    function testConstructorUsdcZeroAddressReverts() public {
        vm.expectRevert(KipuBankV3.InvalidTokenAddress.selector);
        new KipuBankV3(
            100 ether,
            5 ether,
            address(0), // USDC Address 0
            priceFeed,
            6,
            router
        );
    }

    /**
     * @notice Tests that the `getLatestPrice` function reverts with `StalePrice` if the Chainlink price feed data is older than the staleness threshold (3600 seconds).
     * @dev Mocks the Chainlink price feed to simulate an outdated update timestamp.
     */
    function testPriceFeedStaleReverts() public {
        int256 mockPrice = 2000 * 10 ** 8;
        // Simulate that the price was updated more than 3600 seconds (1 hour) ago
        uint256 staleUpdatedAt = block.timestamp - 3601;
        bytes memory response = abi.encode(
            uint80(1),
            mockPrice,
            0,
            staleUpdatedAt, // Stale Timestamp
            0
        );
        vm.mockCall(
            address(kipu.PRICE_FEED()),
            abi.encodeWithSelector(kipu.PRICE_FEED().latestRoundData.selector),
            response
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                KipuBankV3.StalePrice.selector,
                mockPrice,
                staleUpdatedAt
            )
        );
        kipu.getLatestPrice();
    }
}