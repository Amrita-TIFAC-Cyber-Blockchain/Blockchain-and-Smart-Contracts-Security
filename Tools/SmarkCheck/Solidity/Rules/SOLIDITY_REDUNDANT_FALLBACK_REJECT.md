# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_REDUNDANT_FALLBACK_REJECT

![](https://img.shields.io/badge/Pattern_ID-b85a32-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
sourceUnit
                        [pragmaDirective/pragmaSolidity/version[versionLiteral &gt;= "0.4.0"]]
                        /contractDefinition/contractPartDefinition/functionFallBackDefinition/block
                            [count(descendant-or-self::statement) = 1]
                            [statement/throwRevertStatement]
```


### Sample Code

```
pragma solidity 0.4.24;

contract C1 {
    // <yes> <report> SOLIDITY_REDUNDANT_FALLBACK_REJECT b85a32
    function() payable {
        throw;
    }
}
contract C2 {
    // <yes> <report> SOLIDITY_REDUNDANT_FALLBACK_REJECT b85a32
    function() {
        revert();
    }
}
contract C3 {
    function() payable {
        if(msg.sender == address(0)) {
            revert();
        }
    }
}
contract C4 {
    address a;
    function() payable {
        a = msg.sender;
        revert();
    }
}
```