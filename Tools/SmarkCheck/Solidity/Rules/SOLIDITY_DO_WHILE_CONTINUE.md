# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_DO_WHILE_CONTINUE
### Rule Description
Prior to version 0.5.0, Solidity compiler handles code inside do-while loop incorrectly it will ignores code while condition.
### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-94fra3-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
sourceUnit[pragmaDirective
                        [not(//versionOperator) or //versionOperator[text()[1] = "^"]]
                        [//versionLiteral[not(matches(text()[1], "^0\.\s*[5-9]\s*\.|^0\.\s*[0-9]{2,}\s*\.|^[1-9]"))]]]
                    //doWhileStatement
                        [statement//continueStatement
                            [
                                not(ancestor::forStatement[ancestor::doWhileStatement])
                                and not(ancestor::whileStatement[ancestor::doWhileStatement])
                            ]
                        ]
```

### Sample Code

```
pragma solidity ^0.4.24;

contract DoWhileFalse {

    function doWhile() {
        // <yes> <report> SOLIDITY_DO_WHILE_CONTINUE 94fra3
        do {
            continue;
        } while(false);
    }

    function doWhile_2() {
        do {
            while(false) {
                continue;
            }
        } while(false);

        do {
            for(uint i;i<10;i++) {
                continue;
            }
        } while(false);
        // <yes> <report> SOLIDITY_DO_WHILE_CONTINUE 94fra3
        do {
            for(uint j;j<10;j++) {
                continue;
            }
            continue;
        } while(false);
    }
}
```

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/a598063096828250367456ebe5e2e558/68ae004784bda74743e4963c19c4aaec06546a01) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_

### Code Result

```
SOLIDITY_DO_WHILE_CONTINUE
patternId: 94fra3
severity: 1
line: 7
column: 8
content: do{continue;}while(false)

ruleId: SOLIDITY_DO_WHILE_CONTINUE
patternId: 94fra3
severity: 1
line: 25
column: 8
content: do{for(uintj;j<10;j++){continue;}continue;}while(false)

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: 17f23a
severity: 1
line: 14
column: 18
content: false

ruleId: SOLIDITY_PRAGMAS_VERSION
patternId: 23fc32
severity: 1
line: 1
column: 16
content: ^

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 5
column: 4
content: functiondoWhile(){do{continue;}while(false);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 12
column: 4
content: functiondoWhile_2(){do{while(false){continue;}}while(false);do{for(uinti;i<10;i++){continue;}}while(false);do{for(uintj;j<10;j++){continue;}continue;}while(false);}

SOLIDITY_VISIBILITY :2
SOLIDITY_PRAGMAS_VERSION :1
SOLIDITY_GAS_LIMIT_IN_LOOPS :1
SOLIDITY_DO_WHILE_CONTINUE :2

```
