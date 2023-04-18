# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_REWRITE_ON_ASSEMBLY_CALL

![](https://img.shields.io/badge/Pattern_ID-f34j6k-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
assemblyItem
                        [
                            assemblyLocalDefinition/assemblyExpression/assemblyCall
                                [
                                    count(assemblyExpression) = 6
                                    and assemblyExpression[3]/assemblyCall/identifier/text()[1]
                                        = assemblyExpression[5]/assemblyCall/identifier/text()[1]
                                    or count(assemblyExpression) = 7
                                    and assemblyExpression[4]/assemblyCall/identifier/text()[1]
                                        = assemblyExpression[6]/assemblyCall/identifier/text()[1]
                                ]
                            /identifier
                                [matches(text()[1], "^call$|^staticcall$|^callcode$|^delegatecall$")]
                        ]
```

### Sample Code

```
pragma solidity 0.4.24;

contract MixinSignatureValidator {

    function isValidWalletSignature(
        bytes32 hash,
        address walletAddress,
        bytes signature
    )
        internal
        view
        returns (bool isValid)
    {
        bytes memory calldata = abi.encodeWithSelector(
            IWallet(walletAddress).isValidSignature.selector,
            hash,
            signature
        );
        assembly {
            let cdStart := add(calldata, 32)
            // <yes> <report> SOLIDITY_REWRITE_ON_ASSEMBLY_CALL f34j6k
            let success := staticcall(
                gas,              // forward all gas
                walletAddress,    // address of Wallet contract
                cdStart,          // pointer to start of input
                mload(calldata),  // length of input
                cdStart,          // write output over input
                32                // output size is 32 bytes
            )

            switch success
            case 0 {
                // Revert with `Error("WALLET_ERROR")`
                /* snip */
                revert(0, 100)
            }
            case 1 {
                // Signature is valid if call did not revert and returned true
                isValid := mload(cdStart)
            }
        }
        return isValid;
    }

    function () payable public {
        address target = logic_contract;
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, 0, calldatasize)
            let result := delegatecall(gas, target, ptr, calldatasize, 0, 0)
            let size := returndatasize
            returndatacopy(ptr, 0, size)
            switch result
            case 0 { revert(ptr, size) }
            case 1 { return(ptr, size) }
        }
    }
}
```
