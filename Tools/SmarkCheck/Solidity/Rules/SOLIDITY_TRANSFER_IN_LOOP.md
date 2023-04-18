# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_TRANSFER_IN_LOOP

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