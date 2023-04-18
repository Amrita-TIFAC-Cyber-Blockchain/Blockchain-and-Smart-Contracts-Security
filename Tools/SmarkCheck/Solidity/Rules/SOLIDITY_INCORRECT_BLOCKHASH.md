# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_INCORRECT_BLOCKHASH

![](https://img.shields.io/badge/Pattern_ID-b629ad-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
environmentalVariable
                        [matches(text()[1], "^block\.blockhash\($|^blockhash\($")]
                    /expression
                        [
                            primaryExpression/numberLiteral/decimalNumber
                            or environmentalVariable[text()[1] = "block.number"]
                            or (
                                expression[1]/environmentalVariable[text()[1] = "block.number"]
                                and plusminusOperator
                                and expression[2]/primaryExpression/numberLiteral/decimalNumber
                                    [text()[1] > 256]
                            )
                        ]
```


### Sample Code

```
pragma solidity 0.4.24;

contract BlockHash{
    function getBlockBlockhash(uint64 blockNumber) constant returns (bytes32 blockhash){
        // <yes> <report> SOLIDITY_INCORRECT_BLOCKHASH b629ad
        block.blockhash(100);
        // <yes> <report> SOLIDITY_INCORRECT_BLOCKHASH b629ad
        block.blockhash(block.number);
        // <yes> <report> SOLIDITY_INCORRECT_BLOCKHASH b629ad
        block.blockhash(block.number-257);
        block.blockhash(block.number-256);
    }

    function getBlockhash(uint64 blockNumber) constant returns (bytes32 blockhash){
        // <yes> <report> SOLIDITY_INCORRECT_BLOCKHASH b629ad
        blockhash(100);
        // <yes> <report> SOLIDITY_INCORRECT_BLOCKHASH b629ad
        blockhash(block.number);
        // <yes> <report> SOLIDITY_INCORRECT_BLOCKHASH b629ad
        blockhash(block.number-257);
        blockhash(block.number-256);
    }
}
```