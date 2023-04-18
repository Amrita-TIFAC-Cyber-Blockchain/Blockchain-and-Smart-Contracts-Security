# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_DEPRECATED_CONSTRUCTIONS

![](https://img.shields.io/badge/Pattern_ID-27cb59-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
//functionCall/functionName//identifier[matches(text()[1], "^suicide$")]
                    | //assemblyCall/identifier[matches(text()[1], "^suicide$")]
```

![](https://img.shields.io/badge/Pattern_ID-187b5a-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
//functionCall/functionName//identifier[matches(text()[1], "^sha3$")]
                    | //assemblyCall/identifier[matches(text()[1], "^sha3$")]
```

![](https://img.shields.io/badge/Pattern_ID-49bd2a-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
//statement/throwRevertStatement[matches(text()[1], "^throw$")]
```

![](https://img.shields.io/badge/Pattern_ID-28fa69-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
  //functionDefinition[stateMutability/constantType]
```

![](https://img.shields.io/badge/Pattern_ID-852kwn-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
  //numberLiteral/numberUnit[text()[1] = "years"]
```

### Sample Code

```
pragma solidity 0.4.24;

contract C {
    function kill() {
    // <yes> <report> SOLIDITY_DEPRECATED_CONSTRUCTIONS  27cb59
        suicide(0x0);
    }
    function hashingsha3 (string s)   returns  (bytes32 hash){
     // <yes> <report> SOLIDITY_DEPRECATED_CONSTRUCTIONS  187b5a
        return sha3(s);
    }
    function delegatecallSetN(address _e, uint _n) {
    // <yes> <report> SOLIDITY_DEPRECATED_CONSTRUCTIONS  49bd2a
        if (_e != address(0)) throw;
    }
    function killer() {
        uint r;
        assembly {
            // <yes> <report> SOLIDITY_DEPRECATED_CONSTRUCTIONS  187b5a
            r := sha3('','')
            // <yes> <report> SOLIDITY_DEPRECATED_CONSTRUCTIONS  27cb59
            suicide(0x0)
        }
    }
    // <yes> <report> SOLIDITY_DEPRECATED_CONSTRUCTIONS 28fa69
    function returnSenderBalance(uint a) constant returns (uint){
            return a;
    }

    function usingYears() returns(uint) {
    // <yes> <report> SOLIDITY_DEPRECATED_CONSTRUCTIONS 852kwn
        return 100 years;
    }
}
```
