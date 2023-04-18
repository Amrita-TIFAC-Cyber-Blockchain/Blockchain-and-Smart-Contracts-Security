# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_VAR

![](https://img.shields.io/badge/Pattern_ID-d28aa7-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
varDeclaration
                        [expression//primaryExpression/numberLiteral/decimalNumber]
```

![](https://img.shields.io/badge/Pattern_ID-f77619-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
varDeclaration[expression/primaryExpression/identifier]

```



### Sample Code

```
pragma solidity ^0.4.11;

contract SolidityVarZero {
    function foo1() {
        // <yes> <report> SOLIDITY_VAR d28aa7
        for (var i = 0; i < a.length; i ++) { a[i] = i; }
    }
    function foo2() {
        for (uint16 i = 0; i < a.length; i ++) { a[i] = i; }
    }
    function foo3() {
        // <yes> <report> SOLIDITY_VAR f77619
        var a;
        // <yes> <report> SOLIDITY_VAR d28aa7
        var minIdx = 0; /* inferred to uint8 */
        for (var i = minIdx; i < a.length; i++) { a[i] = i; }

    }
}
```