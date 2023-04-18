# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_BYTE_ARRAY_INSTEAD_BYTES

![](https://img.shields.io/badge/Pattern_ID-f13a9f-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
typeName
                        [typeName/elementaryTypeName[text()[1] = "byte"]]
                        [matches(text()[1], "^\[.*\]$")]
```



### Sample Code

```
pragma solidity 0.4.24;
contract C {

    // <yes> <report> SOLIDITY_BYTE_ARRAY_INSTEAD_BYTES f13a9f
    byte[] someVariable1;
    
    bytes someVariable2;
    uint[] data;
}
```