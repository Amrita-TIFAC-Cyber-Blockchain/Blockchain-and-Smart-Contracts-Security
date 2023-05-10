# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_USING_INLINE_ASSEMBLY
### Rule Description
<p>
    Inline assembly is a way to access the Ethereum Virtual Machine at a low level. This discards several important safety features of Solidity.
</p>

### Solidity-Rules

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

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/1c6ce7d9847443b09f58313a99abc970/0c935a817c3b9a7a5f8e5c22913e2a72cb518830) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_


### Code Result

```
SOLIDITY_USING_INLINE_ASSEMBLY.sol
jar:file:/C:/Users/Pothuri%20Harika/AppData/Roaming/npm/node_modules/@smartdec/smartcheck/jdeploy-bundle/smartcheck-2.0-jar-with-dependencies.jar!/solidity-rules.xmlruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 58bdd3
severity: 1
line: 3
column: 4
content: functionat(address_addr)returns(byteso_code){assembly{letsize:=extcodesize(_addr)o_code:=mload(0x40)mstore(0x40,add(o_code,and(add(add(size,0x20),0x1f),not(0x1f))))mstore(o_code,size)extcodecopy(_addr,add(o_code,0x20),0,size)}}

ruleId: SOLIDITY_PRAGMAS_VERSION
patternId: 23fc32
severity: 1
line: 1
column: 16
content: ^

ruleId: SOLIDITY_USING_INLINE_ASSEMBLY
patternId: 109cd5
severity: 1
line: 5
column: 8
content: assembly{letsize:=extcodesize(_addr)o_code:=mload(0x40)mstore(0x40,add(o_code,and(add(add(size,0x20),0x1f),not(0x1f))))mstore(o_code,size)extcodecopy(_addr,add(o_code,0x20),0,size)}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 3
column: 4
content: functionat(address_addr)returns(byteso_code){assembly{letsize:=extcodesize(_addr)o_code:=mload(0x40)mstore(0x40,add(o_code,and(add(add(size,0x20),0x1f),not(0x1f))))mstore(o_code,size)extcodecopy(_addr,add(o_code,0x20),0,size)}}

SOLIDITY_VISIBILITY :1
SOLIDITY_PRAGMAS_VERSION :1
SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN :1
SOLIDITY_USING_INLINE_ASSEMBLY :1

```
