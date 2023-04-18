# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_VAR_IN_LOOP_FOR

![](https://img.shields.io/badge/Pattern_ID-f176ab-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
forStatement
                        [expression[1]/varDeclaration]
                        [condition/expression/expression/primaryExpression
                            [numberLiteral/decimalNumber
                                [matches(text()[1], "^[0-9]+$")]
                                &gt; 255
                            ]
                        ]
                        [expression[2]/twoPlusMinusOperator/incrementOperator]
```

### Sample Code

```
pragma solidity ^0.4.11;

contract SolidityUncheckedSend {
    function unseatKing(address a, uint w) view returns (uint){
    // <yes> <report> SOLIDITY_VAR_IN_LOOP_FOR f176ab
        for (var i = 0; i < 257; i++) {
            a=0;
        }
        for (var i = 0; i < 4; i++) {
            a=0;
        }
        for (var i = 1000; i > 400; i--) {
            a=0;
        }
    }
}
```
