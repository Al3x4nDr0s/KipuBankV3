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

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";


/// @notice Interface for a Uniswap-compatible universal router used to perform token swaps to USDC.
interface IUniversalRouter {
    /// @notice Execute encoded router commands. Forwards ETH when called with value.
    function execute(bytes calldata commands, bytes[] calldata inputs) external payable returns (bytes[] memory results);
}

/// @notice Simplified Permit2-like interface for optional gasless transfers from users to this contract.
interface IPermit2 {
    /// @notice Transfers approved tokens from `from` to `to`. Real Permit2 uses signed data structures.
    function permitTransferFrom(address from, address to, address token, uint256 amount, bytes calldata permit) external;
}

/**
 * @title KipuBankV3
 * @notice Upgraded version of KipuBank that:
 *         - Accepts ETH and ERC20 deposits
 *         - Swaps non-USDC tokens to USDC using a Uniswap-compatible router
 *         - Stores all user balances in USDC (6 decimals)
 * @dev NatSpec follows the V2 style and includes extra details for router & permit integration.
 */
contract KipuBankV3 is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ---------------------------
    // CONSTANTS & IMMUTABLES
    // ---------------------------

    /// @notice USDC token address (6 decimals)
    address public immutable USDC;

    /// @notice Router used to swap arbitrary tokens to USDC (Uniswap-compatible).
    IUniversalRouter public immutable universalRouter;

    /// @notice Optional Permit2 contract address (may be zero if unused).
    IPermit2 public immutable permit2;

    /// @notice Chainlink price feed (optional; for informational purposes).
    AggregatorV3Interface public immutable priceFeed;

    /// @notice Global bank cap denominated in USDC (6 decimals).
    uint256 public immutable bankCapUSDC;

    // ---------------------------
    // STATE
    // ---------------------------

    /// @notice Total USDC deposited/credited across all users (6 decimals).
    uint256 public totalUSDCDeposits;

    /// @notice Mapping user => USDC balance (6 decimals).
    mapping(address => uint256) private userUSDCBalance;

    /// @notice Maximum withdrawal allowed per transaction (6 decimals).
    uint256 public transactionWithdrawalCapUSDC;

    // ---------------------------
    // EVENTS
    // ---------------------------

    /// @notice Emitted when a user's USDC balance increases via deposit or swap.
    event DepositUSDC(address indexed user, uint256 amountUSDC, uint256 newBalanceUSDC);

    /// @notice Emitted when a user withdraws USDC.
    event WithdrawalUSDC(address indexed user, uint256 amountUSDC, uint256 newBalanceUSDC);

    /// @notice Emitted when a token is swapped to USDC on behalf of a user.
    event SwappedToUSDC(address indexed user, address indexed srcToken, uint256 srcAmount, uint256 receivedUSDC);

    /// @notice Emitted when the per-transaction withdrawal cap is updated.
    event TransactionWithdrawalCapUpdated(uint256 newCap);

    // ---------------------------
    // ERRORS
    // ---------------------------

    /// @custom:error ZeroAmount Thrown when a zero amount is provided where a positive amount is required.
    error ZeroAmount();

    /// @custom:error InsufficientBalance Thrown when a user attempts to withdraw more than their balance.
    error InsufficientBalance();

    /// @custom:error ExceedsBankCap Thrown when a deposit would cause total USDC to exceed bankCapUSDC.
    error ExceedsBankCap(uint256 attempted, uint256 cap);

    /// @custom:error ExceedsWithdrawalCap Thrown when a withdrawal exceeds transactionWithdrawalCapUSDC.
    error ExceedsWithdrawalCap(uint256 attempted, uint256 cap);

    /// @custom:error SwapFailed Thrown when a swap via the router did not produce USDC.
    error SwapFailed();

    /// @custom:error InvalidPermit2 Thrown when permit2 flow is requested but Permit2 address is zero.
    error InvalidPermit2();

    // ---------------------------
    // CONSTRUCTOR
    // ---------------------------

    /**
     * @notice Initializes the KipuBankV3 contract.
     * @param _usdc Address of the USDC token (6 decimals).
     * @param _universalRouter Address of a Uniswap-compatible router for swaps to USDC.
     * @param _permit2 Optional Permit2-like contract address for gasless transfers (set to 0 if unused).
     * @param _priceFeed Optional Chainlink price feed address (for information/monitoring).
     * @param _bankCapUSDC Global maximum deposits allowed in USDC (6 decimals).
     * @param _txWithdrawalCapUSDC Per-transaction withdrawal cap in USDC (6 decimals).
     */

    using SafeERC20 for IERC20;

    constructor(
        address _usdc,
        address _universalRouter,
        address _permit2,
        address _priceFeed,
        uint256 _bankCapUSDC,
        uint256 _txWithdrawalCapUSDC
    ) Ownable(msg.sender) {  // <-- Pass initialOwner here
    require(_usdc != address(0), "USDC 0");
    require(_universalRouter != address(0), "router 0");

    USDC = _usdc;
    universalRouter = IUniversalRouter(_universalRouter);
    permit2 = IPermit2(_permit2);
    priceFeed = AggregatorV3Interface(_priceFeed);
    bankCapUSDC = _bankCapUSDC;
    transactionWithdrawalCapUSDC = _txWithdrawalCapUSDC;
}

    // ---------------------------
    // VIEW HELPERS
    // ---------------------------

    /**
     * @notice Returns the USDC-denominated balance of a user.
     * @param user The address of the user.
     * @return The user's balance in USDC (6 decimals).
     */
    function getUserUSDCBalance(address user) external view returns (uint256) {
        return userUSDCBalance[user];
    }

    /**
     * @notice Returns whether adding `amountUSDC` would exceed the bank cap.
     * @param amountUSDC Amount in USDC (6 decimals) to test.
     * @return True if the new total would exceed the bank cap, false otherwise.
     */
    function wouldExceedBankCap(uint256 amountUSDC) public view returns (bool) {
        return (totalUSDCDeposits + amountUSDC) > bankCapUSDC;
    }

    // ---------------------------
    // DEPOSIT & SWAP FLOWS
    // ---------------------------

    /**
     * @notice Deposit native ETH and swap to USDC via the router.
     * @dev Caller must provide `commands` and `inputs` that route received ETH to USDC.
     *      Function records USDC balance before and after router execution to calculate received amount.
     * @param commands Encoded router commands to execute the ETH->USDC swap.
     * @param inputs Array of inputs corresponding to the router commands.
     */
    function depositNativeAndSwap(bytes calldata commands, bytes[] calldata inputs) external payable nonReentrant {
        uint256 ethAmount = msg.value;
        if (ethAmount == 0) revert ZeroAmount();

        // Read balance once
        uint256 before = IERC20(USDC).balanceOf(address(this));

        // Execute router call, forwarding ETH
        try universalRouter.execute{value: ethAmount}(commands, inputs) returns (bytes[] memory) {
            // success path; router expected to send USDC to this contract
        } catch {
            revert SwapFailed();
        }

        uint256 after_ = IERC20(USDC).balanceOf(address(this));
        uint256 receivedUSDC = after_ - before;
        if (receivedUSDC == 0) revert SwapFailed();

        _creditUSDC(msg.sender, receivedUSDC);
        emit SwappedToUSDC(msg.sender, address(0), ethAmount, receivedUSDC);
    }

    /**
     * @notice Deposit an ERC20 token. If token == USDC, credits directly. Otherwise swaps to USDC then credits.
     * @dev Supports optional Permit2-based gasless transfers (mocked interface). Pulls tokens into contract,
     *      approves router only if needed, executes router, and credits resultant USDC.
     * @param token ERC20 token address being deposited.
     * @param amount Amount of the token to deposit (in token decimals).
     * @param usePermit2 If true, calls permit2.permitTransferFrom to move tokens from user to this contract.
     * @param permit Opaque permit data forwarded to permit2 when usePermit2 is true.
     * @param commands Router commands to swap token -> USDC (ignored if token == USDC).
     * @param inputs Router inputs corresponding to `commands`.
     */
    function depositArbitraryToken(
        address token,
        uint256 amount,
        bool usePermit2,
        bytes calldata permit,
        bytes calldata commands,
        bytes[] calldata inputs
    ) external nonReentrant {
        if (amount == 0) revert ZeroAmount();

        if (token == USDC) {
            // Direct credit flow for USDC: single storage writes and event
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
            _creditUSDC(msg.sender, amount);
            return;
        }

        // Pull tokens: either via Permit2 helper or standard transferFrom
        if (usePermit2) {
            if (address(permit2) == address(0)) revert InvalidPermit2();
            permit2.permitTransferFrom(msg.sender, address(this), token, amount, permit);
        } else {
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        }

        // Approve router only if allowance insufficient
        _safeApproveIfNeeded(token, address(universalRouter), amount);

        uint256 before = IERC20(USDC).balanceOf(address(this));

        // Execute swap (router expected to send USDC to this contract)
        try universalRouter.execute(commands, inputs) returns (bytes[] memory) {
        } catch {
            revert SwapFailed();
        }

        uint256 after_ = IERC20(USDC).balanceOf(address(this));
        uint256 receivedUSDC = after_ - before;
        if (receivedUSDC == 0) revert SwapFailed();

        _creditUSDC(msg.sender, receivedUSDC);
        emit SwappedToUSDC(msg.sender, token, amount, receivedUSDC);
    }

    // ---------------------------
    // INTERNAL HELPERS
    // ---------------------------

    /**
     * @notice Internal function that credits user's USDC balance and updates total deposits.
     * @dev Performs minimal storage writes: totalUSDCDeposits and userUSDCBalance updated once each.
     * @param user Address to credit.
     * @param amountUSDC USDC amount (6 decimals).
     */
    function _creditUSDC(address user, uint256 amountUSDC) internal {
        uint256 newTotal = totalUSDCDeposits + amountUSDC;
        if (newTotal > bankCapUSDC) revert ExceedsBankCap(newTotal, bankCapUSDC);

        // single writes to storage
        totalUSDCDeposits = newTotal;
        uint256 newBalance = userUSDCBalance[user] + amountUSDC;
        userUSDCBalance[user] = newBalance;

        emit DepositUSDC(user, amountUSDC, newBalance);
    }

    /**
     * @notice Withdraw USDC from the caller's balance.
     * @dev Enforces per-transaction cap and updates storage only once per variable.
     * @param amountUSDC Amount to withdraw in USDC (6 decimals).
     */
    function withdrawUSDC(uint256 amountUSDC) external nonReentrant {
        if (amountUSDC == 0) revert ZeroAmount();
        if (amountUSDC > transactionWithdrawalCapUSDC) revert ExceedsWithdrawalCap(amountUSDC, transactionWithdrawalCapUSDC);

        uint256 balance = userUSDCBalance[msg.sender];
        if (amountUSDC > balance) revert InsufficientBalance();

        uint256 newBalance = balance - amountUSDC;
        userUSDCBalance[msg.sender] = newBalance;
        totalUSDCDeposits -= amountUSDC;

        IERC20(USDC).safeTransfer(msg.sender, amountUSDC);
        emit WithdrawalUSDC(msg.sender, amountUSDC, newBalance);
    }

    /**
     * @notice Approve spender for token if allowance is insufficient.
     * @param token Token address.
     * @param spender Spender address (router).
     * @param amount Required amount to approve.
     */
    function _safeApproveIfNeeded(address token, address spender, uint256 amount) internal {
        IERC20 erc = IERC20(token);
        uint256 allowance = erc.allowance(address(this), spender);
        if (allowance < amount) {
            if (allowance != 0) {
                erc.safeApprove(spender, 0);
            }
            erc.safeApprove(spender, amount);
        }
    }

    // ---------------------------
    // OWNER ACTIONS
    // ---------------------------

    /**
     * @notice Update the transaction withdrawal cap (USDC 6 decimals).
     * @param newCap New per-transaction cap in USDC (6 decimals).
     */
    function setTransactionWithdrawalCapUSDC(uint256 newCap) external onlyOwner {
        transactionWithdrawalCapUSDC = newCap;
        emit TransactionWithdrawalCapUpdated(newCap);
    }

    /**
     * @notice Emergency recovery for tokens other than USDC.
     * @param token Token address to recover.
     * @param amount Amount to transfer.
     * @param to Recipient address.
     */
    function emergencyWithdrawToken(address token, uint256 amount, address to) external onlyOwner {
        require(token != USDC, "cannot withdraw USDC");
        IERC20(token).safeTransfer(to, amount);
    }

    /**
     * @notice Prevent accidental direct ETH transfers; require depositNativeAndSwap for ETH.
     */
    receive() external payable {
        revert("No direct ETH");
    }
}