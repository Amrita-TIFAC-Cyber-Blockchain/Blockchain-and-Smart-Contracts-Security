# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_UNCHECKED_CALL
### Rule Description
<p>
    A function with <code>public</code> visibility modifier that is not called internally. Changing visibility level to <code>external</code> increases code readability. Moreover, in many cases functions with <code>external</code> visibility modifier spend less gas comparing to functions with <code>public</code> visibility modifier.
</p>

### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-f39eed-gold) ![](https://img.shields.io/badge/Severity-3-brown) 

```
functionCall
                        [
                            functionName//identifier
                                [matches(text()[1], "^call$|^delegatecall$|^send$|^callcode$")]
                            and not(ancestor::ifStatement)
                            and not(ancestor::returnStatement)
                            and not(ancestor::functionCall)
                            and not(ancestor::variableDeclarationStatement)
                            and not(ancestor::expression and ancestor::expression[text()[1] = "=" or lvalueOperator])
                        ]
```

### Sample Code

```
pragma solidity 0.4.24;

interface Deff {
    function deff(bool) external;
    function sendTokens(uint) external;
}

contract SolidityUncheckedSend {
    function unseatKing(address a, uint w) public {
        // <yes> <report> SOLIDITY_UNCHECKED_CALL f39eed
        a.call.value(w)();
        // <yes> <report> SOLIDITY_UNCHECKED_CALL f39eed
        a.send(w);
        // <yes> <report> SOLIDITY_UNCHECKED_CALL f39eed
        a.delegatecall(w);
        // <yes> <report> SOLIDITY_UNCHECKED_CALL f39eed
        a.callcode(w);
    }

    function delegatecallSetN(address _e, uint _n) public {
        if (!_e.delegatecall(bytes4(sha3("setN(uint256)")), _n)) revert();
    }

    function delegatecallSetN1(address _e, uint _n) public {
        if (!_e.call(bytes4(sha3("setN(uint256)")), _n)) revert();
    }

    function delegatecallSetN2(address _e, uint _n) public {
        if (!_e.send(1)) revert();
    }
    function delegatecallSetN3(address _e, uint _n) public {
        require(_e.call(bytes4(sha3("setN(uint256)")), _n));
    }

    function delegatecallSetN4(address _e, uint _n) public {
        assert(_e.call(bytes4(sha3("setN(uint256)")), _n));
    }

    function delegatecallSetN5(address _e, uint _n) public {
        assert(_e.callcode(bytes4(sha3("setN(uint256)")), _n));
    }

    function returnSend(address a) public returns (bool) {
        return a.send(1);
    }

    function checkArg(bool arg) public returns (bool) {
        return arg;
    }

    function functionArgumentSend(address a) public returns (bool) {
        return checkArg(a.send(1));
    }

    function f1(address y, address a, address d) public {
        bool x = y.send(1);
        checkArg(a.send(1));
        Deff f = Deff(a);
        f.deff(d.send(1));
        Deff(d).sendTokens(1);
    }

    function foo() external {
        (bool x, ) = address(0x144f7887b6c42982b83A0A33fDDc9a4E9b378CaF).call("abc");
        require(x);
    }
}
```

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/629aca3b71d5a207b35206afbfc04e20/7c60be4835e19320b58732440345f71bd52931f9) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_


### Code Result

```
SOLIDITY_ADDRESS_HARDCODED
patternId: adc165
severity: 1
line: 64
column: 29
content: 0x144f7887b6c42982b83A0A33fDDc9a4E9b378CaF

ruleId: SOLIDITY_CALL_WITHOUT_DATA
patternId: om991k
severity: 2
line: 11
column: 10
content: call.value(w)()

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 187b5a
severity: 1
line: 21
column: 36
content: sha3

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 187b5a
severity: 1
line: 25
column: 28
content: sha3

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 187b5a
severity: 1
line: 32
column: 31
content: sha3

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 187b5a
severity: 1
line: 36
column: 30
content: sha3

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 187b5a
severity: 1
line: 40
column: 34
content: sha3

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 21
column: 8
content: if(!_e.delegatecall(bytes4(sha3("setN(uint256)")),_n))revert();

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 25
column: 8
content: if(!_e.call(bytes4(sha3("setN(uint256)")),_n))revert();

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 29
column: 8
content: if(!_e.send(1))revert();

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 11
column: 10
content: call.value(w)()

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 13
column: 10
content: send(w)

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 15
column: 10
content: delegatecall(w)

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 17
column: 10
content: callcode(w)

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 60
column: 16
content: sendTokens(1)

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 64
column: 73
content: call("abc")

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 11
column: 10
content: call.value(w)()

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 25
column: 16
content: call(bytes4(sha3("setN(uint256)")),_n)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 32
column: 19
content: call(bytes4(sha3("setN(uint256)")),_n)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 36
column: 18
content: call(bytes4(sha3("setN(uint256)")),_n)

SOLIDITY_DEPRECATED_CONSTRUCTIONS :5
SOLIDITY_REVERT_REQUIRE :3
SOLIDITY_ADDRESS_HARDCODED :1
SOLIDITY_UPGRADE_TO_050 :4
SOLIDITY_UNCHECKED_CALL :6
SOLIDITY_CALL_WITHOUT_DATA :1

```
