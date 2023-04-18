# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_CALL_WITHOUT_DATA

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