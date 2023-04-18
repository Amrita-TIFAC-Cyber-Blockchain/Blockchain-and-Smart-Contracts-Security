# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_SEND

![](https://img.shields.io/badge/Pattern_ID-430636-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
expression
                        [text()[1] = "."]
                        [not(expression[1]/typeConversion/typeName/elementaryTypeName[matches(text()[1], "^address$|^address payable$")])]
                        /functionCall
                            [functionName/identifier[text()[1] = "send"]]
                            [callArguments/tupleExpression[count(expression) = 1]]
                            [
                                ancestor::condition
                                    [expression/text()[1] = "!"]
                                    /parent::ifStatement/statement/block/statement/throwRevertStatement
                                or ancestor::functionCall
                                    [not(callArguments/tupleExpression/expression/text()[1] = "!")]
                                    /functionName/identifier
                                        [matches(text()[1], "^require$|^assert$")]
                            ]
```

![](https://img.shields.io/badge/Pattern_ID-we5gu5-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
expression
                        [text()[1] = "."]
                        [expression[1]/typeConversion/typeName/elementaryTypeName[matches(text()[1], "^address$|^address payable$")]]
                        /functionCall
                            [functionName/identifier[text()[1] = "send"]]
                            [callArguments/tupleExpression[count(expression) = 1]]
                            [
                                ancestor::condition
                                    [expression/text()[1] = "!"]
                                    /parent::ifStatement/statement/block/statement/throwRevertStatement
                                or ancestor::functionCall
                                    [not(callArguments/tupleExpression/expression/text()[1] = "!")]
                                    /functionName/identifier
                                        [matches(text()[1], "^require$|^assert$")]
                            ]
```



### Sample Code

```
pragma solidity 0.4.24;

contract SoliditySend {

    function payOut() {
        uint i=50;
        while ( i < 100 && msg.gas > 200000) {
            msg.sender.send(msg.value);
            i++;
        }
        if (true) {
            msg.sender.send(1);
            revert();
        }
        if (msg.sender.send(1)) { revert();}
        if (address(msg.sender).send(1)) { throw;}
        require(!address payable(msg.sender).send(1));
        assert(!address payable(uint160(msg.sender)).send(1));

// <yes> <report> SOLIDITY_SEND 430636
        if (!msg.sender.send(1)) { revert();}
// <yes> <report> SOLIDITY_SEND 430636
        if (!msg.sender.send(1)) { throw;}
// <yes> <report> SOLIDITY_SEND 430636
        require(msg.sender.send(1));
// <yes> <report> SOLIDITY_SEND 430636
        assert(msg.sender.send(1));
        // <yes> <report> SOLIDITY_SEND we5gu5
        if (!address(msg.sender).send(1)) { revert();}
        // <yes> <report> SOLIDITY_SEND we5gu5
        if (!address(msg.sender).send(1)) { throw;}
        // <yes> <report> SOLIDITY_SEND we5gu5
        require(address(msg.sender).send(1));
        // <yes> <report> SOLIDITY_SEND we5gu5
        assert(address(msg.sender).send(1));
        // <yes> <report> SOLIDITY_SEND we5gu5
        if (!address payable(msg.sender).send(1)) { revert();}
        // <yes> <report> SOLIDITY_SEND we5gu5
        if (!address payable(msg.sender).send(1)) { throw;}
        // <yes> <report> SOLIDITY_SEND we5gu5
        require(address payable(msg.sender).send(1));
        // <yes> <report> SOLIDITY_SEND we5gu5
        assert(address payable(uint160(msg.sender)).send(1));
    }
}
```