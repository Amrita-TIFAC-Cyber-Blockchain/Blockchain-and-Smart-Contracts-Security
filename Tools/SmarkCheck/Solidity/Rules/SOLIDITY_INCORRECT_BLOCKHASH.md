# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_INCORRECT_BLOCKHASH
### Rule Description
<p>
    <code>blockhash</code> function returns a non-zero value only for 256 last blocks. Besides, it always returns 0 for the current block, i.e. <code>blockhash(block.number)</code> always equals to 0.
</p>

### Solidity-Rules

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

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/68f4866e7f27e43b61182f734ef3d8d3/6c6915df0b7dddb6688e8eb8415b89d22dd8082b) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_

### Code Result

```
SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 28fa69
severity: 1
line: 4
column: 4
content: functiongetBlockBlockhash(uint64blockNumber)constantreturns(bytes32blockhash){block.blockhash(100);block.blockhash(block.number);block.blockhash(block.number-257);block.blockhash(block.number-256);}

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 28fa69
severity: 1
line: 14
column: 4
content: functiongetBlockhash(uint64blockNumber)constantreturns(bytes32blockhash){blockhash(100);blockhash(block.number);blockhash(block.number-257);blockhash(block.number-256);}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 58bdd3
severity: 1
line: 4
column: 4
content: functiongetBlockBlockhash(uint64blockNumber)constantreturns(bytes32blockhash){block.blockhash(100);block.blockhash(block.number);block.blockhash(block.number-257);block.blockhash(block.number-256);}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 58bdd3
severity: 1
line: 14
column: 4
content: functiongetBlockhash(uint64blockNumber)constantreturns(bytes32blockhash){blockhash(100);blockhash(block.number);blockhash(block.number-257);blockhash(block.number-256);}

ruleId: SOLIDITY_INCORRECT_BLOCKHASH
patternId: b629ad
severity: 2
line: 6
column: 24
content: 100

ruleId: SOLIDITY_INCORRECT_BLOCKHASH
patternId: b629ad
severity: 2
line: 8
column: 24
content: block.number

ruleId: SOLIDITY_INCORRECT_BLOCKHASH
patternId: b629ad
severity: 2
line: 10
column: 24
content: block.number-257

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 4
column: 4
content: functiongetBlockBlockhash(uint64blockNumber)constantreturns(bytes32blockhash){block.blockhash(100);block.blockhash(block.number);block.blockhash(block.number-257);block.blockhash(block.number-256);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 14
column: 4
content: functiongetBlockhash(uint64blockNumber)constantreturns(bytes32blockhash){blockhash(100);blockhash(block.number);blockhash(block.number-257);blockhash(block.number-256);}

SOLIDITY_VISIBILITY :2
SOLIDITY_DEPRECATED_CONSTRUCTIONS :2
SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN :2
SOLIDITY_INCORRECT_BLOCKHASH :3


```
