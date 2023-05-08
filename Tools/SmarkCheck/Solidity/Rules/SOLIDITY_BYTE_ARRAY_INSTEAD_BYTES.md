# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_BYTE_ARRAY_INSTEAD_BYTES
### Rule Description
Lower gas consumption
### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-f13a9f-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
typeName
                        [typeName/elementaryTypeName[text()[1] = "byte"]]
                        [matches(text()[1], "^\[.*\]$")]
```



### Sample Code

```
pragma solidity 0.4.24;
contract C {

    // <yes> <report> SOLIDITY_BYTE_ARRAY_INSTEAD_BYTES f13a9f
    byte[] someVariable1;
    
    bytes someVariable2;
    uint[] data;
}
```

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/81c00d2664b3a76545a8024e42c8a238/489d5aa42067fb6025a78c853016c00806d06a3f) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_

### Code Result

```
SOLIDITY_BYTE_ARRAY_INSTEAD_BYTES
patternId: f13a9f
severity: 1
line: 5
column: 4
content: byte[]

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 5
column: 4
content: byte[]someVariable1;

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 7
column: 4
content: bytessomeVariable2;

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 8
column: 4
content: uint[]data;

SOLIDITY_VISIBILITY :3
SOLIDITY_BYTE_ARRAY_INSTEAD_BYTES :1


```
