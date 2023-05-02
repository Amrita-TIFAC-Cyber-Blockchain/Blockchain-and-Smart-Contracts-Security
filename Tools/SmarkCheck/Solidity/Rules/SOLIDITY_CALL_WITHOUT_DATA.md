# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_CALL_WITHOUT_DATA
### Rule Description
Use of low-level code call function with no arguments provided.


### Solidity-Rules
![](https://img.shields.io/badge/Pattern_ID-om991k-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
functionCall
                        [functionName/identifier[text()[1] = "call"]]
                        [not(callArguments//expression)]
                        [not(gas/expression)]

```

![](https://img.shields.io/badge/Pattern_ID-lr991l-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
functionCall
                        [functionName/identifier[text()[1] = "call"]]
                        [callArguments//stringLiteral[string-length(text()) = 0]]
                        [callArguments/tupleExpression[count(expression) = 1]]
                        [not(gas/expression)]
```

![](https://img.shields.io/badge/Pattern_ID-111ttt-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
functionCall
                        [functionName/identifier[text()[1] = "call"]]
                        [callArguments//stringLiteral[string-length(text()) = 0]]
                        [callArguments/tupleExpression[count(expression) = 1]]
                        [gas/expression]
```

### Sample Code

```
pragma solidity 0.4.24;

contract CallValue {

    function withdraw1() {
    // <yes> <report> SOLIDITY_CALL_WITHOUT_DATA om991k
        if (msg.sender.call.value(1)()) {
        }
    }
    function withdraw2() {
    // <yes> <report> SOLIDITY_CALL_WITHOUT_DATA om991k
        if (msg.sender.call()) {
        }
    }
    function withdraw3() {
    // <yes> <report> SOLIDITY_CALL_WITHOUT_DATA lr991l
        if (msg.sender.call.gas(100000)()) {
        }
    }
    function withdraw4() {
        if (msg.sender.call.value(1)(3)) {
        }
    }
    function withdraw5() {
        // <yes> <report> SOLIDITY_CALL_WITHOUT_DATA 111ppp
        if (msg.sender.call.value(1)("")) {
        }
    }
    function withdraw6() {
        // <yes> <report> SOLIDITY_CALL_WITHOUT_DATA 111ppp
        if (msg.sender.call("")) {
        }
    }
    function withdraw7() {
        // <yes> <report> SOLIDITY_CALL_WITHOUT_DATA 111ttt
        if (msg.sender.call.gas(100000)("")) {
        }
    }
    function withdraw8() {
        if (msg.sender.call.value(1)(" ")) {
        }
    }
    function withdraw9() {
        if (msg.sender.call("", 1)) {
        }
    }
    function withdraw10() {
        if (msg.sender.call.gas(100000)("", 1)) {
        }
    }
}
```

### Code Result

```
SOLIDITY_CALL_WITHOUT_DATA
patternId: om991k
severity: 2
line: 7
column: 23
content: call.value(1)()

ruleId: SOLIDITY_CALL_WITHOUT_DATA
patternId: om991k
severity: 2
line: 12
column: 23
content: call()

ruleId: SOLIDITY_CALL_WITHOUT_DATA
patternId: lr991l
severity: 1
line: 17
column: 23
content: call.gas(100000)()

ruleId: SOLIDITY_CALL_WITHOUT_DATA
patternId: 111ppp
severity: 2
line: 26
column: 23
content: call.value(1)("")

ruleId: SOLIDITY_CALL_WITHOUT_DATA
patternId: 111ppp
severity: 2
line: 31
column: 23
content: call("")

ruleId: SOLIDITY_CALL_WITHOUT_DATA
patternId: 111ttt
severity: 1
line: 36
column: 23
content: call.gas(100000)("")

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 7
column: 23
content: call.value(1)()

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 12
column: 23
content: call()

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 17
column: 23
content: call.gas(100000)()

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 44
column: 23
content: call("",1)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 48
column: 23
content: call.gas(100000)("",1)

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 5
column: 4
content: functionwithdraw1(){if(msg.sender.call.value(1)()){}}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 10
column: 4
content: functionwithdraw2(){if(msg.sender.call()){}}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 15
column: 4
content: functionwithdraw3(){if(msg.sender.call.gas(100000)()){}}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 20
column: 4
content: functionwithdraw4(){if(msg.sender.call.value(1)(3)){}}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 24
column: 4
content: functionwithdraw5(){if(msg.sender.call.value(1)("")){}}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 29
column: 4
content: functionwithdraw6(){if(msg.sender.call("")){}}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 34
column: 4
content: functionwithdraw7(){if(msg.sender.call.gas(100000)("")){}}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 39
column: 4
content: functionwithdraw8(){if(msg.sender.call.value(1)(" ")){}}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 43
column: 4
content: functionwithdraw9(){if(msg.sender.call("",1)){}}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 47
column: 4
content: functionwithdraw10(){if(msg.sender.call.gas(100000)("",1)){}}

SOLIDITY_VISIBILITY :10
SOLIDITY_UPGRADE_TO_050 :5
SOLIDITY_CALL_WITHOUT_DATA :6


```
