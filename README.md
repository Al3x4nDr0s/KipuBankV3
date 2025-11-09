# KipuBankV3_NatSpec

KipuBankV3 with full NatSpec documentation (in English) preserved from V2 plus V3 additions.
Project prepared for Foundry tests and production integration.

## Structure

```
.
├── src
│   ├── KipuBankV3.sol
│   ├── MockUSDC.sol
│   ├── MockERC20.sol
│   ├── MockUniversalRouter.sol
│   └── MockPermit2.sol
├── test
│   └── KipuBankV3.t.sol
├── foundry.toml
└── README.md
```

## Quickstart (Foundry)

Install Foundry: https://getfoundry.sh

```bash
forge build
forge test
```

## Usage notes

- Replace mocks with actual Universal Router and Permit2 addresses in production.
- Build router `commands` + `inputs` off-chain (Uniswap v4 docs).
- Use Tenderly to simulate router payloads and debug before mainnet deployment.

## License

MIT
