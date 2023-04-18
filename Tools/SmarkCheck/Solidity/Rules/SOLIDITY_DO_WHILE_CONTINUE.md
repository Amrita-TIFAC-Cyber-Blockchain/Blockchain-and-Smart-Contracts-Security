# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_DO_WHILE_CONTINUE

![](https://img.shields.io/badge/Pattern_ID-94fra3-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
sourceUnit[pragmaDirective
                        [not(//versionOperator) or //versionOperator[text()[1] = "^"]]
                        [//versionLiteral[not(matches(text()[1], "^0\.\s*[5-9]\s*\.|^0\.\s*[0-9]{2,}\s*\.|^[1-9]"))]]]
                    //doWhileStatement
                        [statement//continueStatement
                            [
                                not(ancestor::forStatement[ancestor::doWhileStatement])
                                and not(ancestor::whileStatement[ancestor::doWhileStatement])
                            ]
                        ]
```



### Sample Code

```
pragma solidity ^0.4.24;

contract DoWhileFalse {

    function doWhile() {
        // <yes> <report> SOLIDITY_DO_WHILE_CONTINUE 94fra3
        do {
            continue;
        } while(false);
    }

    function doWhile_2() {
        do {
            while(false) {
                continue;
            }
        } while(false);

        do {
            for(uint i;i<10;i++) {
                continue;
            }
        } while(false);
        // <yes> <report> SOLIDITY_DO_WHILE_CONTINUE 94fra3
        do {
            for(uint j;j<10;j++) {
                continue;
            }
            continue;
        } while(false);
    }
}
```