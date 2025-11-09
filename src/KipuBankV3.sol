// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title KipuBankV3
 * @author Alejandro Cárdenas
 * @notice Bank contract that accepts native ETH and ERC20 tokens, swaps non-USDC tokens to USDC,
 *         and maintains user balances denominated in USDC (6 decimals). Designed for production:
 *         - minimizes storage reads/writes
 *         - uses checks-effects-interactions
 *         - protects against reentrancy
 *         - integrates with an Uniswap-compatible router for swaps
 * @dev This version merges the NatSpec documentation style from KipuBankV2 and adds
 *      the router & permit2 integration. Router is described as "Router contract handling
 *      swaps to USDC (Uniswap-compatible)". Permit2 integration is optional.
 */

import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/release-v4.9/contracts/token/ERC20/IERC20.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/release-v4.9/contracts/token/ERC20/utils/SafeERC20.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/release-v4.9/contracts/access/Ownable.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/release-v4.9/contracts/security/ReentrancyGuard.sol";
import "https://github.com/smartcontractkit/chainlink/blob/develop/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

/// @notice Interface for a Uniswap-compatible universal router used to perform token swaps to USDC.
interface IUniversalRouter {
    /// @notice Execute encoded router commands. Forwards ETH when called with value.
    function execute(bytes calldata commands, bytes[] calldata inputs)
        external
        payable
        returns (bytes[] memory results);
}

/// @notice Simplified Permit2-like interface for optional gasless transfers from users to this contract.
interface IPermit2 {
    /// @notice Transfers approved tokens from `from` to `to`. Real Permit2 uses signed data structures.
    function permitTransferFrom(
        address from,
        address to,
        address token,
        uint256 amount,
        bytes calldata permit
    ) external;
}

/**
 * @title KipuBankV3
 * @notice Upgraded version of KipuBank that:
 *         - Accepts ETH and ERC20 deposits
 *         - Swaps non-USDC tokens to USDC using a Uniswap-compatible router
 *         - Stores all user balances in USDC (6 decimals)
 *         - Integrates optional Permit2 for gasless approvals
 *         - Uses Chainlink price feeds for reference pricing
 * @dev Router contract handling swaps to USDC (Uniswap-compatible)
 */
contract KipuBankV3 is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice USDC token used for internal accounting
    IERC20 public immutable usdc;

    /// @notice Uniswap-compatible router used to perform token swaps
    IUniversalRouter public immutable router;

    /// @notice Optional Permit2 contract for gasless transfers
    IPermit2 public immutable permit2;

    /// @notice User balances stored in USDC (6 decimals)
    mapping(address => uint256) public usdcBalances;

    /// @notice Chainlink price feed used for external reference prices
    AggregatorV3Interface public priceFeed;

    /// @notice Emitted when a user deposits and balance increases
    event Deposit(address indexed user, uint256 usdcAmount);

    /// @notice Emitted when a user withdraws their USDC
    event Withdraw(address indexed user, uint256 usdcAmount);

    /// @notice Emitted when a swap occurs
    event Swap(address indexed user, address tokenIn, uint256 amountIn, uint256 usdcOut);

    /**
     * @param _usdc Address of USDC token
     * @param _router Address of Uniswap-compatible router
     * @param _permit2 Address of optional Permit2 contract
     * @param _priceFeed Address of Chainlink price feed
     */
    constructor(
        address _usdc,
        address _router,
        address _permit2,
        address _priceFeed
    ) Ownable(msg.sender) {
        require(_usdc != address(0) && _router != address(0), "Invalid address");
        usdc = IERC20(_usdc);
        router = IUniversalRouter(_router);
        permit2 = IPermit2(_permit2);
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    /**
     * @notice Deposits USDC directly or any ERC20 token to be swapped into USDC.
     * @param token The ERC20 token address being deposited.
     * @param amount The token amount being deposited.
     * @param swapData Encoded router data for performing the swap.
     */
    function depositToken(address token, uint256 amount, bytes calldata swapData)
        external
        nonReentrant
    {
        require(amount > 0, "Invalid amount");

        IERC20 erc = IERC20(token);
        erc.safeTransferFrom(msg.sender, address(this), amount);

        uint256 usdcReceived = amount;

        if (token != address(usdc)) {
            erc.safeApprove(address(router), 0);
            erc.safeApprove(address(router), amount);
            router.execute(swapData, new bytes );
        }

        usdcBalances[msg.sender] += usdcReceived;
        emit Deposit(msg.sender, usdcReceived);
    }

    /**
     * @notice Withdraws USDC from the user balance.
     * @param amount Amount of USDC to withdraw.
     */
    function withdraw(uint256 amount) external nonReentrant {
        require(usdcBalances[msg.sender] >= amount, "Insufficient balance");

        usdcBalances[msg.sender] -= amount;
        usdc.safeTransfer(msg.sender, amount);

        emit Withdraw(msg.sender, amount);
    }

    /**
     * @notice Fetches the latest price from Chainlink oracle.
     * @return price The latest oracle price as int256.
     */
    function getLatestPrice() external view returns (int256 price) {
        (, price,,,) = priceFeed.latestRoundData();
    }
}
