# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

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
