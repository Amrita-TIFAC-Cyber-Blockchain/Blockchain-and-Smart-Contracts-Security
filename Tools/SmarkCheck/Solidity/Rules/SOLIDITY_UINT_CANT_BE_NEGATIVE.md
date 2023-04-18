# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_UINT_CANT_BE_NEGATIVE

![](https://img.shields.io/badge/Pattern_ID-11ca45b-gold) ![](https://img.shields.io/badge/Severity-3-brown) 

```
(forStatement | whileStatement | doWhileStatement)
                        /condition/expression
                            [text()[1] = ">="]
                            [expression[2]/primaryExpression//decimalNumber[text()[1] = "0"]]
                            [expression[1]/primaryExpression/identifier
                                [text()[1]
                                    = ancestor::functionDefinition//variableDeclaration
                                        [typeName/elementaryTypeName[matches(text()[1], "uint")]]
                                        /identifier/text()[1]
                                ]
                            ]
```

![](https://img.shields.io/badge/Pattern_ID-d48ac4-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
expression
                        [text()[1] = ">="]
                        [expression[2]/primaryExpression//decimalNumber[text()[1] = "0"]]
                        [expression[1]/(primaryExpression/identifier | identifier)
                            [
                                text()[1]
                                    = ancestor::functionDefinition//variableDeclaration
                                        [typeName/elementaryTypeName[matches(text()[1], "uint")]]
                                        /identifier/text()[1]
                                or text()[1]
                                    = ancestor::contractDefinition//(structDefinition/variableDeclaration | stateVariableDeclaration)
                                        [typeName/elementaryTypeName[matches(text()[1], "uint")]]
                                        /identifier/text()[1]
                            ]
                        ]
```

![](https://img.shields.io/badge/Pattern_ID-733fdd-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
expression
                        [text()[1]=">="]
                        [expression[2]//decimalNumber[text()[1] = "0"]]
                        [expression[1]/expression[1]//identifier
                            [text()[1]
                                = ancestor::contractDefinition//stateVariableDeclaration
                                    [typeName/mappingSt/typeName[2]/elementaryTypeName[matches(text()[1],"uint")]]
                                    /identifier/text()[1]
                            ]
                        ]
```

### Sample Code

```
pragma solidity 0.4.24;

contract UnderFlow {
    uint8 a;

    function foo_1() {
        uint b;
        int c = 1;
    // <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  11ca45b <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  d48ac4
        for (uint i=100; i >= 0; i--) {
        }
        for (uint j=0; j <= 0; j--) {
        }
        for (uint k=100; k >= 1; k--) {
        }
    // <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  d48ac4
        require(a >= 0);
        require(a <= 0);
    // <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  d48ac4
        require(b >= 0);
        require(b >= 7);
        require(c >= 0);
    }

    struct Mystruct {
        uint a1;
        int a2;
    }

    function foo_2(Mystruct str) internal {
    // <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  d48ac4
        require(str.a1 >= 0);
        require(str.a2 >= 0);
    }

    mapping(address => uint) balances;
    mapping(address => int) ibalances;

    function foo_3(address user) {
    // <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  733fdd
        require(balances[user] >= 0);
        require(ibalances[user] >= 0);
    }

    function foo_4() {
        uint i;
    // <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  11ca45b <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  d48ac4
        while(i >= 0) {
            i--;
        }
        do {
            i--;
    // <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  11ca45b <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  d48ac4
        } while(i >=0);

        for (uint i=100; i <= 0; i++) {
    // <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  11ca45b <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  d48ac4
            for (uint i=100; i >= 0; i--) {
            }
        }
    }
}
```
