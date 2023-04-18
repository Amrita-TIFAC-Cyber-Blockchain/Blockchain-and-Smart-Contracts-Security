# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_USING_INLINE_ASSEMBLY

![](https://img.shields.io/badge/Pattern_ID-109cd5-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
statement/inlineAssemblyStatement/inlineAssemblyBlock
                        [not(assemblyItem/assemblyAssignment
                            [assemblyExpression/assemblyCall/identifier
                                [matches(text()[1], "^extcodesize$")]
                            ])
                        ]
                        /ancestor::inlineAssemblyStatement
```

### Sample Code

```
pragma solidity ^0.4.18;
library GetCode {
    function at( address _addr) returns (bytes o_code) {
    // <yes> <report> SOLIDITY_USING_INLINE_ASSEMBLY 109cd5
        assembly {
            let size := extcodesize(_addr)
            o_code := mload(0x40)
            mstore(0x40, add(o_code, and(add(add(size, 0x20), 0x1f), not(0x1f))))
            mstore(o_code, size)
            extcodecopy(_addr, add(o_code, 0x20), 0, size)
        }
    }
    function isContract(address addr) private returns (bool) {
        uint _size;
        assembly { _size := extcodesize(addr) }
        return _size > 0;
    }
}
```
