# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)<br/> 
![](https://img.shields.io/badge/Tool-Silther-blue)


## SOLIDITY_PRIVATE_MODIFIER_DOES_NOT_HIDE_DATA
### Rule Description
<p>
    Contrary to a popular misconception, the <code>private</code> modifier does not make a variable invisible. Miners have access to all contracts’ code and data. Developers must account for the lack of privacy in Ethereum.
</p>
<p>
    Vulnerability type by SmartDec classification: <a href="https://github.com/smartdec/classification#privacy">
    Privacy</a>.
</p>

### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-5616b2-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
stateVariableDeclaration/visibleType[text()[1] = "private"]
```

### Sample Code

```
pragma solidity 0.4.24;

contract MarketPlace {
    // <yes> <report> SOLIDITY_PRIVATE_MODIFIER_DOES_NOT_HIDE_DATA 5616b2
    uint private data1;
    
    uint data2;
}
```

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/5419f10cfd2da6c14fd071f830581e96/77e8f5dfd7edd995f74270a9d5b979c354f84518) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_

### Code Result

```
SOLIDITY_PRIVATE_MODIFIER_DONT_HIDE_DATA
patternId: 5616b2
severity: 1
line: 5
column: 9
content: private

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 7
column: 4
content: uintdata2;

SOLIDITY_VISIBILITY :1
SOLIDITY_PRIVATE_MODIFIER_DONT_HIDE_DATA :1

```

# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)<br/> 
![](https://img.shields.io/badge/Tool-Silther-blue)

## Silther Result
```
INFO:Detectors:
Pragma version0.4.24 (SOLIDITY_PRIVATE_MODIFIER_DOES_NOT_HIDE_DATA.sol#1) allows old versions
solc-0.4.24 is not recommended for deployment
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity
INFO:Detectors:
MarketPlace.data1 (SOLIDITY_PRIVATE_MODIFIER_DOES_NOT_HIDE_DATA.sol#5) should be constant
MarketPlace.data2 (SOLIDITY_PRIVATE_MODIFIER_DOES_NOT_HIDE_DATA.sol#7) should be constant
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#state-variables-that-could-be-declared-constant
INFO:Slither:SOLIDITY_PRIVATE_MODIFIER_DOES_NOT_HIDE_DATA.sol analyzed (1 contracts with 85 detectors), 4 result(s) found
```
