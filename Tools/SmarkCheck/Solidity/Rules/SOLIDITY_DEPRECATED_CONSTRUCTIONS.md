# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_DEPRECATED_CONSTRUCTIONS
### Rule Description
Deprecated constructions
### Solidity-Rules

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

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/cebc0980b1be99cd5ed88b8c85e929dd/b0800a58bab995065466b0276ee3fa75f2a19a02) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_

### Code Result

```
SOLIDITY_ADDRESS_HARDCODED
patternId: c67a09
severity: 1
line: 6
column: 16
content: 0x0

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 27cb59
severity: 1
line: 6
column: 8
content: suicide

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 27cb59
severity: 1
line: 22
column: 12
content: suicide

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 187b5a
severity: 1
line: 10
column: 15
content: sha3

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 187b5a
severity: 1
line: 20
column: 17
content: sha3

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 49bd2a
severity: 1
line: 14
column: 30
content: throw

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 28fa69
severity: 1
line: 26
column: 4
content: functionreturnSenderBalance(uinta)constantreturns(uint){returna;}

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 852kwn
severity: 1
line: 32
column: 19
content: years

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 14
column: 8
content: if(_e!=address(0))throw;

ruleId: SOLIDITY_USING_INLINE_ASSEMBLY
patternId: 109cd5
severity: 1
line: 18
column: 8
content: assembly{r:=sha3('','')suicide(0x0)}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 4
column: 4
content: functionkill(){suicide(0x0);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 8
column: 4
content: functionhashingsha3(strings)returns(bytes32hash){returnsha3(s);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 12
column: 4
content: functiondelegatecallSetN(address_e,uint_n){if(_e!=address(0))throw;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 16
column: 4
content: functionkiller(){uintr;assembly{r:=sha3('','')suicide(0x0)}}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 26
column: 4
content: functionreturnSenderBalance(uinta)constantreturns(uint){returna;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 30
column: 4
content: functionusingYears()returns(uint){return100years;}

SOLIDITY_VISIBILITY :6
SOLIDITY_DEPRECATED_CONSTRUCTIONS :7
SOLIDITY_REVERT_REQUIRE :1
SOLIDITY_ADDRESS_HARDCODED :1
SOLIDITY_USING_INLINE_ASSEMBLY :1


```


