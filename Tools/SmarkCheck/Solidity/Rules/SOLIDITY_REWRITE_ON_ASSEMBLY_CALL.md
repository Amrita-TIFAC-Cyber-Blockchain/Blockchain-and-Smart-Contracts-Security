# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_REWRITE_ON_ASSEMBLY_CALL
### Rule Description
<p>
    Dangerous use of inline assembly instruction of <code>CALL</code> family, which overwrites the input with the output.
    In case the arbitrary address is called return value may differ from expected one.
</p>

### Solidity-Rules

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

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/aa0b52bca154c4266d720f6ed8b0abd5/931c75664e8375004c0849182343d96ab86f3c7b) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_

### Code Result

```
SOLIDITY_LOCKED_MONEY
patternId: 30281d
severity: 3
line: 3
column: 0
content: contractMixinSignatureValidator{functionisValidWalletSignature(bytes32hash,addresswalletAddress,bytessignature)internalviewreturns(boolisValid){bytesmemorycalldata=abi.encodeWithSelector(IWallet(walletAddress).isValidSignature.selector,hash,signature);assembly{letcdStart:=add(calldata,32)letsuccess:=staticcall(gas,walletAddress,cdStart,mload(calldata),cdStart,32)switchsuccesscase0{revert(0,100)}case1{isValid:=mload(cdStart)}}returnisValid;}function()payablepublic{addresstarget=logic_contract;assembly{letptr:=mload(0x40)calldatacopy(ptr,0,calldatasize)letresult:=delegatecall(gas,target,ptr,calldatasize,0,0)letsize:=returndatasizereturndatacopy(ptr,0,size)switchresultcase0{revert(ptr,size)}case1{return(ptr,size)}}}}

ruleId: SOLIDITY_SHOULD_NOT_BE_VIEW
patternId: 189abf
severity: 1
line: 5
column: 4
content: functionisValidWalletSignature(bytes32hash,addresswalletAddress,bytessignature)internalviewreturns(boolisValid){bytesmemorycalldata=abi.encodeWithSelector(IWallet(walletAddress).isValidSignature.selector,hash,signature);assembly{letcdStart:=add(calldata,32)letsuccess:=staticcall(gas,walletAddress,cdStart,mload(calldata),cdStart,32)switchsuccesscase0{revert(0,100)}case1{isValid:=mload(cdStart)}}returnisValid;}

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 91h3sa
severity: 1
line: 45
column: 24
content: public

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 8
column: 8
content: bytessignature

ruleId: SOLIDITY_USING_INLINE_ASSEMBLY
patternId: 109cd5
severity: 1
line: 19
column: 8
content: assembly{letcdStart:=add(calldata,32)letsuccess:=staticcall(gas,walletAddress,cdStart,mload(calldata),cdStart,32)switchsuccesscase0{revert(0,100)}case1{isValid:=mload(cdStart)}}

ruleId: SOLIDITY_USING_INLINE_ASSEMBLY
patternId: 109cd5
severity: 1
line: 47
column: 8
content: assembly{letptr:=mload(0x40)calldatacopy(ptr,0,calldatasize)letresult:=delegatecall(gas,target,ptr,calldatasize,0,0)letsize:=returndatasizereturndatacopy(ptr,0,size)switchresultcase0{revert(ptr,size)}case1{return(ptr,size)}}

SOLIDITY_LOCKED_MONEY :1
SOLIDITY_UPGRADE_TO_050 :2
SOLIDITY_USING_INLINE_ASSEMBLY :2
SOLIDITY_SHOULD_NOT_BE_VIEW :1

```

