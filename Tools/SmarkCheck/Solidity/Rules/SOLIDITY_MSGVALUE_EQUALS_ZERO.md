# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_MSGVALUE_EQUALS_ZERO
### Rule Description
<p>
    The <code>msg.value == 0</code> condition check is meaningless in most cases.
</p>

### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-1df89a-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
expression
                        [expression[1]/environmentalVariable[text()[1] = "msg.value"]]
                        [comparison[text()[1] = "=="]]
                        [expression[2]/primaryExpression//decimalNumber[text()[1] = "0"]]
                        [not(ancestor::functionDefinition[text()[1] = "constructor"])]
                        [not(ancestor::functionDefinition/identifier[text()[1]
                            = (ancestor::contractDefinition/identifier)])
                        ]
```

### Sample Code

```
pragma solidity 0.4.24;

contract MsgValue {

    constructor() public {
        require(msg.value == 0);
    }

    function myFunc() public returns(uint) {
        // <yes> <report> SOLIDITY_MSGVALUE_EQUALS_ZERO 1df89a
        require(msg.value == 0);
        // <yes> <report> SOLIDITY_MSGVALUE_EQUALS_ZERO 1df89a
        if(msg.value == 0) {
            return(1);
        }
        // <yes> <report> SOLIDITY_MSGVALUE_EQUALS_ZERO 1df89a
        assert(msg.value == 0);
    }

    function() {
        // <yes> <report> SOLIDITY_MSGVALUE_EQUALS_ZERO 1df89a
        require(msg.value == 0);
    }
}

contract MsgValue2 {

    function MsgValue2() {
        require(msg.value == 0);
    }
}
```

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/2b6b1e6d8d56a08d4a1173aa579e2c2a/2979556ee23227a659d4cec029bf24fbff291654) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_

### Code Result

```
SOLIDITY_MSGVALUE_EQUALS_ZERO
patternId: 1df89a
severity: 1
line: 11
column: 16
content: msg.value==0

ruleId: SOLIDITY_MSGVALUE_EQUALS_ZERO
patternId: 1df89a
severity: 1
line: 13
column: 11
content: msg.value==0

ruleId: SOLIDITY_MSGVALUE_EQUALS_ZERO
patternId: 1df89a
severity: 1
line: 17
column: 15
content: msg.value==0

ruleId: SOLIDITY_MSGVALUE_EQUALS_ZERO
patternId: 1df89a
severity: 1
line: 22
column: 16
content: msg.value==0

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 20
column: 4
content: function(){require(msg.value==0);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 28
column: 4
content: functionMsgValue2(){require(msg.value==0);}

SOLIDITY_VISIBILITY :2
SOLIDITY_MSGVALUE_EQUALS_ZERO :4


```
