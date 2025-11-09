// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {KipuBankV3} from "../src/KipuBankV3.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract KipuBankV3Test is Test {
    KipuBankV3 public kipu;
    address usdc = address(0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238);
    address priceFeed = address(0x694AA1769357215DE4FAC081bf1f309aDC325306);
    address router = address(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
    address ape = address(0x45faf7923BAb5A5380515E055CA700519B3e4705);
    address admin = address(this);
    address user = address(0x123);
    address user2 = address(0x456);

    function setUp() public {
        // Fork desde el RPC definido en tu .env
        vm.createSelectFork(vm.envString("RPC"));

        // Desplegar el contrato
        kipu = new KipuBankV3(
            100 ether,     // _bankCap = 100 ether
            5 ether,       // _maxWithdrawalPerTx = 5 ether
            usdc,
            priceFeed,
            6,        // Decimales del token USDC
            router
        );

        // Configurar permisos
        kipu.addToWhitelist(user);
        kipu.addToWhitelist(user2);
        kipu.grantRole(kipu.DEPOSITOR_ROLE(), user);
        kipu.grantRole(kipu.WITHDRAWER_ROLE(), user);

        // Simular un deposito inicial de USDC por parte de 'user'
        deal(usdc, user, 1_000 * 10**6); // Asignar 1000 USDC (6 decimales) al usuario
        vm.startPrank(user);
        IERC20(usdc).approve(address(kipu), 100 * 10**6); // Aprobar 100 USDC
        kipu.depositUsdc(100 * 10**6); // Depositar 100 USDC
        vm.stopPrank();

    }

    function testDepositEth() public {
        vm.prank(user);
        kipu.depositEth{value: 1 ether}();
        assertEq(kipu.userEthBalances(user), 1 ether);
        assertEq(kipu.totalEth(), 1 ether);
    }


    function testGetLatestPrice() public view{
        console.log("testGetLatestPrice");
        int256 price = kipu.getLatestPrice();
        assert(price > 0);
    }

    function testReceiveFallbackReverts() public{
        console.log("testReceiveFallbackReverts");
        (bool ok1, ) = address(kipu).call{value: 1 ether}("");
        assertFalse(ok1);
        (bool ok2, ) = address(kipu).call(abi.encodeWithSignature("nonexistent()"));
        assertFalse(ok2);
    }
}