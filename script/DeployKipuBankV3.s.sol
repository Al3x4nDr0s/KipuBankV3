// SPDX-License-Identifier: UNLICENCED
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";
import {KipuBankV3} from "../src/KipuBankV3.sol";

contract DeployKipuBankV3 is Script {
    function run() external returns (KipuBankV3) {
        KipuBankV3 kipuBankV3;
        address _usdcAddress = address(0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238);
        address _priceFeedAddress = address(0x694AA1769357215DE4FAC081bf1f309aDC325306);
        address _uniswapRouter = address(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
        vm.startBroadcast();
        kipuBankV3 = new KipuBankV3(100000000000000000000,5000000000000000000,_usdcAddress,_priceFeedAddress, 6,_uniswapRouter);
        return kipuBankV3;
        vm.stopBroadcast();
    }

    function setUp() public {}

}