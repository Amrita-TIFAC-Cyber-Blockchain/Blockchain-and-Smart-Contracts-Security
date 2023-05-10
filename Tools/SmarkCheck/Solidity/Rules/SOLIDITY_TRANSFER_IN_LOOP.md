# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_TRANSFER_IN_LOOP
### Rule Description
<p>
    ETH is transferred in a loop. If at least one address cannot receive ETH (e.g. it is a contract with default fallback function), the whole transaction will be reverted.
</p>
<p>
    Vulnerability type by SmartDec classification: <a href="https://github.com/smartdec/classification#contract-interaction">
    DoS with revert</a>.
</p>

### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-8jdj43-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
statement
                        [forStatement or whileStatement or doWhileStatement]
                        [descendant::functionCall
                            [functionName/identifier[text()[1] = "transfer"]]
                            [callArguments/tupleExpression[count(expression) = 1]]
                        ]
```

### Sample Code

```
pragma solidity 0.4.24;

contract ERC20Token {
    function transfer(address to, uint value) returns(bool);
}

contract TransferInCycle {
    address[] users;
    mapping(address => uint) balances;

    function dangerousWithdraw() returns (bool) {
        uint l = users.length;
        // <yes> <report> SOLIDITY_TRANSFER_IN_LOOP 8jdj43
        for(uint i; i < l; i++) {
            users[i].transfer(balances[users[i]]);
        }
        i=0;
        // <yes> <report> SOLIDITY_TRANSFER_IN_LOOP 8jdj43
        while(i < l) {
            users[i].transfer(balances[users[i]]);
            i++;
        }
    }

    function goodPrictice(address token) {
        uint l = users.length;
        uint i;
        while(i < l) {
            ERC20Token(token).transfer(users[i], balances[users[i]]);
            i++;
        }
    }
}
```

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/55cc5e14e6f147bdae1ead7568b8f233/16f15e101d7cf92c3d118da11935973aab849c75) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_


### Code Result

```
SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 47acc2
severity: 1
line: 11
column: 4
content: functiondangerousWithdraw()returns(bool){uintl=users.length;for(uinti;i<l;i++){users[i].transfer(balances[users[i]]);}i=0;while(i<l){users[i].transfer(balances[users[i]]);i++;}}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 14
column: 8
content: for(uinti;i<l;i++){users[i].transfer(balances[users[i]]);}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: 17f23a
severity: 1
line: 19
column: 14
content: i<l

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: 17f23a
severity: 1
line: 28
column: 14
content: i<l

ruleId: SOLIDITY_TRANSFER_IN_LOOP
patternId: 8jdj43
severity: 2
line: 14
column: 8
content: for(uinti;i<l;i++){users[i].transfer(balances[users[i]]);}

ruleId: SOLIDITY_TRANSFER_IN_LOOP
patternId: 8jdj43
severity: 2
line: 19
column: 8
content: while(i<l){users[i].transfer(balances[users[i]]);i++;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 4
column: 4
content: functiontransfer(addressto,uintvalue)returns(bool);

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 11
column: 4
content: functiondangerousWithdraw()returns(bool){uintl=users.length;for(uinti;i<l;i++){users[i].transfer(balances[users[i]]);}i=0;while(i<l){users[i].transfer(balances[users[i]]);i++;}}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 25
column: 4
content: functiongoodPrictice(addresstoken){uintl=users.length;uinti;while(i<l){ERC20Token(token).transfer(users[i],balances[users[i]]);i++;}}

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 8
column: 4
content: address[]users;

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 9
column: 4
content: mapping(address=>uint)balances;

SOLIDITY_VISIBILITY :5
SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN :1
SOLIDITY_GAS_LIMIT_IN_LOOPS :3
SOLIDITY_TRANSFER_IN_LOOP :2

```
