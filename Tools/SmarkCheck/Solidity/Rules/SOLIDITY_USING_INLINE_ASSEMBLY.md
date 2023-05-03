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

### Code Result

```
ruleId: SOLIDITY_CALL_WITHOUT_DATA
patternId: om991k
severity: 2
line: 7
column: 23
content: call()

ruleId: SOLIDITY_CALL_WITHOUT_DATA
patternId: om991k
severity: 2
line: 9
column: 14
content: call()

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 58bdd3
severity: 1
line: 43
column: 4
content: functionnumberTwo1()publicreturns(uint[]a){}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 58bdd3
severity: 1
line: 46
column: 4
content: functionnumberTwo1_1()returns(uint[]a){}

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 7
column: 23
content: call()

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 9
column: 14
content: call()

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 11
column: 14
content: call(a,b)

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 12
column: 14
content: call(2+2)

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 13
column: 14
content: call(abi.encodePacked(a,b))

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 15
column: 23
content: call(a,b)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 7
column: 23
content: call()

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 9
column: 14
content: call()

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 11
column: 14
content: call(a,b)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 15
column: 23
content: call(a,b)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 901eae
severity: 1
line: 17
column: 21
content: keccak256(a,b)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 91h3sa
severity: 1
line: 21
column: 16
content: private

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 91h3sa
severity: 1
line: 59
column: 16
content: internal

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 91h3sa
severity: 1
line: 90
column: 16
content: public

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 5
column: 49
content: bytesb

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 34
column: 23
content: uint[]a

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 40
column: 24
content: bytesa

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 40
column: 33
content: stringb

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 43
column: 41
content: uint[]a

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 51
column: 24
content: Usera

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 441gim
severity: 1
line: 67
column: 8
content: uint[]a

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 441gim
severity: 1
line: 84
column: 8
content: Usera

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 37
column: 4
content: functionnumberTwo_1(uint[]a){}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 46
column: 4
content: functionnumberTwo1_1()returns(uint[]a){}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 54
column: 4
content: functionnumberTwo3_1(Usera){}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 82
column: 4
content: functionnumberOne(){Usera;Userstorageb=userStruct;Usermemoryc=userStruct;}

ruleId: SOLIDITY_VISIBILITY
patternId: d67c21
severity: 1
line: 21
column: 16
content: private

ruleId: SOLIDITY_VISIBILITY
patternId: d67c21
severity: 1
line: 59
column: 16
content: internal

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 64
column: 4
content: uint[]intArray;

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 81
column: 4
content: UseruserStruct;

SOLIDITY_VISIBILITY :8
SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN :2
SOLIDITY_UPGRADE_TO_050 :16
SOLIDITY_UNCHECKED_CALL :6
SOLIDITY_CALL_WITHOUT_DATA :2

```
