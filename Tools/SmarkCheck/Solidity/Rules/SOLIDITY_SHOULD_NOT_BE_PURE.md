# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_SHOULD_NOT_BE_PURE
### Rule Description
<p>In Solidity, function that do not read from the state or modify it can be declared as <code>pure</code>.
</p>

### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-11314f-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
functionDefinition
                        [
                            stateMutability/pureType
                            and block/descendant-or-self::*
                                [   <!--Accessing <address>.balance: using .balance-->
                                    expression[matches(text()[1], "\.balance")]
                                    <!--Accessing any of the members of block, tx, msg (with the exception of msg.sig and msg.data)-->
                                    or environmentalVariable[matches(text()[1], "msg\.value|msg\.gas|msg\.sender|block\.timestamp|tx\.origin|block\.blockhash|block\.coinbase|block\.difficulty|block\.gaslimit|block\.number|block\.blockhash|block\.coinbase|tx\.gasprice")]
                                    <!--Using selfdestruct and it's alias suicide:-->
                                    or functionCall/functionName//identifier[matches(text()[1], "^selfdestruct$|^suicide$")]
                                    <!--Sending Ether via calls:-->
                                    or functionCall/functionName//identifier[matches(text()[1], "^send$|^transfer$")]
                                    <!--Using low-level calls:-->
                                    or functionCall/functionName//identifier[matches(text()[1], "^call$|^delegatecall$|^callcode$")]
                                    <!--Using inline assembly that contains certain opcodes:-->
                                    or inlineAssemblyStatement
                                ]
                        ]
```

### Sample Code

```
pragma solidity ^0.4.16;

contract C {
    address f;
// <yes> <report> SOLIDITY_SHOULD_NOT_BE_PURE 11314f
    function returnsenderbalance() pure returns (uint){
         return msg.sender.balance;
    }
// <yes> <report> SOLIDITY_SHOULD_NOT_BE_PURE 11314f
    function returnsenderbalance() pure returns (uint){
        if (f < this.balance) x.send(10);
        return t;
    }
// <yes> <report> SOLIDITY_SHOULD_NOT_BE_PURE 11314f
    function returnsenderbalance() pure returns (uint){
        y=msg.value;
        o=block.timestamp;
        return t;
    }
    // <yes> <report> SOLIDITY_SHOULD_NOT_BE_PURE 11314f
    function returnsenderbalance() pure returns (uint){
        y=msg.value;
        o=block.timestamp;
        selfdestruct(f);
        return t;
    }
    function returnsenderbalance() pure returns (uint){
        return t;
    }
    function test() pure public returns (string memory name) {
        name = type(Math).name;
    }
}
contract Math {
    function Mul(uint a, uint b) pure internal returns (uint) {
      uint c = a * b;
      //check result should not be other wise until a=0
      assert(a == 0 || c / a == b);
      return c;
    }
}
```

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/14aff10a00dee0abaa5aefea19b06b67/240082f90aa3338f718f482b61e83381c3b516c2) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_


### Code Result

```
SOLIDITY_PRAGMAS_VERSION
patternId: 23fc32
severity: 1
line: 1
column: 16
content: ^

ruleId: SOLIDITY_SHOULD_NOT_BE_PURE
patternId: 11314f
severity: 1
line: 6
column: 4
content: functionreturnsenderbalance()purereturns(uint){returnmsg.sender.balance;}

ruleId: SOLIDITY_SHOULD_NOT_BE_PURE
patternId: 11314f
severity: 1
line: 10
column: 4
content: functionreturnsenderbalance()purereturns(uint){if(f<this.balance)x.send(10);returnt;}

ruleId: SOLIDITY_SHOULD_NOT_BE_PURE
patternId: 11314f
severity: 1
line: 15
column: 4
content: functionreturnsenderbalance()purereturns(uint){y=msg.value;o=block.timestamp;returnt;}

ruleId: SOLIDITY_SHOULD_NOT_BE_PURE
patternId: 11314f
severity: 1
line: 21
column: 4
content: functionreturnsenderbalance()purereturns(uint){y=msg.value;o=block.timestamp;selfdestruct(f);returnt;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 6
column: 4
content: functionreturnsenderbalance()purereturns(uint){returnmsg.sender.balance;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 10
column: 4
content: functionreturnsenderbalance()purereturns(uint){if(f<this.balance)x.send(10);returnt;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 15
column: 4
content: functionreturnsenderbalance()purereturns(uint){y=msg.value;o=block.timestamp;returnt;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 21
column: 4
content: functionreturnsenderbalance()purereturns(uint){y=msg.value;o=block.timestamp;selfdestruct(f);returnt;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 27
column: 4
content: functionreturnsenderbalance()purereturns(uint){returnt;}

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 4
column: 4
content: addressf;

SOLIDITY_VISIBILITY :6
SOLIDITY_PRAGMAS_VERSION :1
SOLIDITY_SHOULD_NOT_BE_PURE :4

```
