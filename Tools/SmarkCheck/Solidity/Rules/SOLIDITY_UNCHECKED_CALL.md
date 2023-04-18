# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_UNCHECKED_CALL

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