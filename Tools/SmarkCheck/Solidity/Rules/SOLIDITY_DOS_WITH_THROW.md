# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_DOS_WITH_THROW
### Rule Description
Prior to version 0.5.0, Solidity compiler handles code inside do-while loop incorrectly it will ignores code while condition.
### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-637fdc-gold) ![](https://img.shields.io/badge/Severity-3-brown) 

```
//ifStatement[condition//externalFunctionCall][block/statement//throwRevertStatement]
```

![](https://img.shields.io/badge/Pattern_ID-efb788-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
//forStatement/expression//externalFunctionCall
```

![](https://img.shields.io/badge/Pattern_ID-04242c-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
//whileStatement/whileCondition//externalFunctionCall
```

### Sample Code

```
pragma solidity ^0.4.5;
contract Auction {
    /* address addr;
    function bid() payable {
        // <_yes> <report> SOLIDITY_DOS_WITH_THROW 637fdc
        if (currentLeader.send(highestBid)) { throw; }
        // <_yes> <report> SOLIDITY_DOS_WITH_THROW 637fdc
        if (!currentLeader.send(highestBid)) { revert; } 

        // <_yes> <report> SOLIDITY_DOS_WITH_THROW efb788
        for(uint x; x < refundAddresses[x].transfer(1 wei); x++) {
            addr.transfer(1 wei);
        }

        // <_yes> <report> SOLIDITY_DOS_WITH_THROW 04242c
        while ( x > refundAddresses[x].transfer(1 wei)) {
            refundAddresses[x].transfer(1 wei);
        }
    } */
}
```

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/7187fed7b8ca3bf082fde599520416ec/8efed1a840fd11ee8f5c19f0963783dd2b95f4dc) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_


### Code Result

```
SOLIDITY_PRAGMAS_VERSION
patternId: 23fc32
severity: 1
line: 1
column: 16
content: ^

SOLIDITY_PRAGMAS_VERSION :1

```
