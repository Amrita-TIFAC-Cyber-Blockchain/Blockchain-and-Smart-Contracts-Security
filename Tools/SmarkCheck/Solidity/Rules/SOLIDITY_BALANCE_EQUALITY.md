# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_BALANCE_EQUALITY
### Rule Description
The balance is checked for strict equality.Avoid checking for strict balance equality:an adversary can forcibly send ether to any address via selfdestruct() or by mining.
### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-5094ad-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
expression
                        [comparison]
                        [
                            expression[matches(text()[1], "\.balance$")]
                            or expression/tupleExpression/expression[matches(text()[1], "\.balance$")]
                            or expression/expression[matches(text()[1], "\.balance$")]
                        ]

```


### Sample Code

```
pragma solidity 0.6.0;

contract C {

    function badPrictice(address addr) public {
        // <yes> <report> SOLIDITY_BALANCE_EQUALITY 5094ad
        if (this.balance == 100 wei) {
        }
        // <yes> <report> SOLIDITY_BALANCE_EQUALITY 5094ad
        if (address(this).balance != 100 wei) {
        }
        // <yes> <report> SOLIDITY_BALANCE_EQUALITY 5094ad
        if (addr.balance != 100 wei) {
        }
        // <yes> <report> SOLIDITY_BALANCE_EQUALITY 5094ad
        if((addr.balance) == 0) {
        }
        // <yes> <report> SOLIDITY_BALANCE_EQUALITY 5094ad
        if(1 + addr.balance == 0) {
        }
    }

    function myFoo(uint[] memory a) public returns(uint) {
        a[1];
        a[1:];
        a[:2];
        return a[1:2];
    }

    function goodPrictice(address addr) public {
        if(myFoo(addr.balance) == 0) {
        }
        if (this.balance > 100 wei) {
        }
        if (address(this).balance >= 100 wei) {
        }
        if (addr.balance <= 100 wei) {
        }
        if (msg.sender.balance < 100 wei) {
        }
        if (foo(addr).balance >= 100 wei) {
        }
    }

    function foo(address _addr) public returns(address) {
        return _addr;
    }
}  
```

### Code Result

```
SOLIDITY_BALANCE_EQUALITY
patternId: 5094ad
severity: 1
line: 7
column: 12
content: this.balance==100wei

ruleId: SOLIDITY_BALANCE_EQUALITY
patternId: 5094ad
severity: 1
line: 10
column: 12
content: address(this).balance!=100wei

ruleId: SOLIDITY_BALANCE_EQUALITY
patternId: 5094ad
severity: 1
line: 13
column: 12
content: addr.balance!=100wei

ruleId: SOLIDITY_BALANCE_EQUALITY
patternId: 5094ad
severity: 1
line: 16
column: 11
content: (addr.balance)==0

ruleId: SOLIDITY_BALANCE_EQUALITY
patternId: 5094ad
severity: 1
line: 19
column: 11
content: 1+addr.balance==0

SOLIDITY_BALANCE_EQUALITY :5

```
