# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)<br/> 
![](https://img.shields.io/badge/Tool-Silther-blue)

## SOLIDITY_PRAGMAS_VERSION
### Rule Description
<p>
    Solidity source files indicate the versions of the compiler they can be compiled with.
</p>
<pre>
<code>
pragma solidity ^0.4.17; // bad: compiles w 0.4.17 and above
pragma solidity 0.4.24; // good : compiles w 0.4.24 only
</code>
</pre>
<p>
    It is recommended to follow the latter example, as future compiler versions may handle certain language constructions in a way the developer did not foresee.
</p>

### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-23fc32-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
pragmaDirective/pragmaSolidity//versionOperator
```

### Sample Code

```
<yes> <report> SOLIDITY_PRAGMAS_VERSION 23fc32
pragma solidity ^0.4.21;

pragma solidity 0.4.24;
```

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/6c66e1bf12437792ac7442c020f09831/c3e453b421eb13f4fe129283509f704d4a9797bd) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_

### Code Result

```
SOLIDITY_PRAGMAS_VERSION
patternId: 23fc32
severity: 1
line: 2
column: 16
content: ^

SOLIDITY_PRAGMAS_VERSION :1


```

## Silther Result

```
INFO:SlitherSolcParsing:No contract were found in None, check the correct compilation
INFO:Detectors:
Different versions of Solidity are used:
        - Version used: ['0.4.24', '^0.4.21']
        - 0.4.24 (SOLIDITY_PRAGMAS_VERSION.sol#4-5)
        - ^0.4.21 (SOLIDITY_PRAGMAS_VERSION.sol#2)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#different-pragma-directives-are-used
INFO:Detectors:
Pragma version^0.4.21 (SOLIDITY_PRAGMAS_VERSION.sol#2) allows old versions
Pragma version0.4.24 (SOLIDITY_PRAGMAS_VERSION.sol#4-5) allows old versions
solc-0.4.24 is not recommended for deployment
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity
WARNING:Slither:No contract was analyzed
INFO:Slither:SOLIDITY_PRAGMAS_VERSION.sol analyzed (0 contracts with 85 detectors), 4 result(s) found
```
