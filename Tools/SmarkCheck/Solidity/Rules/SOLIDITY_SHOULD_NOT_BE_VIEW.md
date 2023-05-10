# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_SHOULD_NOT_BE_VIEW
### Rule Description
<p>In Solidity, functions that do not read from the state or modify it can be declared as <code>view</code>.</p>

### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-189abf-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
functionDefinition
                        [
                            stateMutability/viewType
                            and block/descendant-or-self::*
                                [   <!--Using selfdestruct and it's alias suicide:-->
                                    functionCall/functionName//identifier[matches(text()[1], "^selfdestruct$|^suicide$")]
                                    <!--Sending Ether via calls:-->
                                    or functionCall/functionName//identifier[matches(text()[1], "^send$|^transfer$")]
                                    <!--Using low-level calls:-->
                                    or functionCall/functionName//identifier[matches(text()[1], "^call$|^delegatecall$|^callcode$")]
                                    <!--Using inline assembly that contains certain opcodes:-->
                                    or inlineAssemblyStatement
                                ]
                        ]
```

### Sample Code

```
pragma solidity ^0.4.11;

contract SolidityUncheckedSend {
// <yes> <report> SOLIDITY_SHOULD_NOT_BE_VIEW 189abf
    function unseatKing(address a, uint w) view returns (uint){
        selfdestruct(a);
        }

// <yes> <report> SOLIDITY_SHOULD_NOT_BE_VIEW 189abf
    function unseatKing(address a, uint w) view returns (uint){
        suicide(a);
        }

    // <yes> <report> SOLIDITY_SHOULD_NOT_BE_VIEW 189abf
    function unseatKing(address a, uint w) view returns (uint){
        x.transfer(10);
        }

    // <yes> <report> SOLIDITY_SHOULD_NOT_BE_VIEW 189abf
    function unseatKing(address a, uint w) view returns (uint){
        x.send(10);
        }

    function unseatKing(address a, uint w) returns (uint){
        x.job(10);
        }
    // <yes> <report> SOLIDITY_SHOULD_NOT_BE_VIEW 189abf
    function unseatKing(address a, uint w) view returns (uint){
        namReg.call.gas(1000000)("register", "MyName");
        }
        // <yes> <report> SOLIDITY_SHOULD_NOT_BE_VIEW 189abf
    function at(address _addr) view returns (uint) {
        assembly{
            let
            size := extcodesize(_addr)
            extcodecopy(_addr, add(o_code, 0x20), 0, size)
            }
        }
}
```

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/4a14bca8f224e6e84bea8eeab41ac9d6/5f380092b8274414d5591d58d9fe1a8735f30676) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_


### Code Result

```
SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 27cb59
severity: 1
line: 11
column: 8
content: suicide

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 47acc2
severity: 1
line: 5
column: 4
content: functionunseatKing(addressa,uintw)viewreturns(uint){selfdestruct(a);}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 47acc2
severity: 1
line: 10
column: 4
content: functionunseatKing(addressa,uintw)viewreturns(uint){suicide(a);}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 47acc2
severity: 1
line: 15
column: 4
content: functionunseatKing(addressa,uintw)viewreturns(uint){x.transfer(10);}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 47acc2
severity: 1
line: 20
column: 4
content: functionunseatKing(addressa,uintw)viewreturns(uint){x.send(10);}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 47acc2
severity: 1
line: 24
column: 4
content: functionunseatKing(addressa,uintw)returns(uint){x.job(10);}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 47acc2
severity: 1
line: 28
column: 4
content: functionunseatKing(addressa,uintw)viewreturns(uint){namReg.call.gas(1000000)("register","MyName");}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 47acc2
severity: 1
line: 32
column: 4
content: functionat(address_addr)viewreturns(uint){assembly{letsize:=extcodesize(_addr)extcodecopy(_addr,add(o_code,0x20),0,size)}}

ruleId: SOLIDITY_PRAGMAS_VERSION
patternId: 23fc32
severity: 1
line: 1
column: 16
content: ^

ruleId: SOLIDITY_SHOULD_NOT_BE_VIEW
patternId: 189abf
severity: 1
line: 5
column: 4
content: functionunseatKing(addressa,uintw)viewreturns(uint){selfdestruct(a);}

ruleId: SOLIDITY_SHOULD_NOT_BE_VIEW
patternId: 189abf
severity: 1
line: 10
column: 4
content: functionunseatKing(addressa,uintw)viewreturns(uint){suicide(a);}

ruleId: SOLIDITY_SHOULD_NOT_BE_VIEW
patternId: 189abf
severity: 1
line: 15
column: 4
content: functionunseatKing(addressa,uintw)viewreturns(uint){x.transfer(10);}

ruleId: SOLIDITY_SHOULD_NOT_BE_VIEW
patternId: 189abf
severity: 1
line: 20
column: 4
content: functionunseatKing(addressa,uintw)viewreturns(uint){x.send(10);}

ruleId: SOLIDITY_SHOULD_NOT_BE_VIEW
patternId: 189abf
severity: 1
line: 28
column: 4
content: functionunseatKing(addressa,uintw)viewreturns(uint){namReg.call.gas(1000000)("register","MyName");}

ruleId: SOLIDITY_SHOULD_NOT_BE_VIEW
patternId: 189abf
severity: 1
line: 32
column: 4
content: functionat(address_addr)viewreturns(uint){assembly{letsize:=extcodesize(_addr)extcodecopy(_addr,add(o_code,0x20),0,size)}}

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 21
column: 10
content: send(10)

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 29
column: 15
content: call.gas(1000000)("register","MyName")

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 29
column: 15
content: call.gas(1000000)("register","MyName")

ruleId: SOLIDITY_USING_INLINE_ASSEMBLY
patternId: 109cd5
severity: 1
line: 33
column: 8
content: assembly{letsize:=extcodesize(_addr)extcodecopy(_addr,add(o_code,0x20),0,size)}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 5
column: 4
content: functionunseatKing(addressa,uintw)viewreturns(uint){selfdestruct(a);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 10
column: 4
content: functionunseatKing(addressa,uintw)viewreturns(uint){suicide(a);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 15
column: 4
content: functionunseatKing(addressa,uintw)viewreturns(uint){x.transfer(10);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 20
column: 4
content: functionunseatKing(addressa,uintw)viewreturns(uint){x.send(10);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 24
column: 4
content: functionunseatKing(addressa,uintw)returns(uint){x.job(10);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 28
column: 4
content: functionunseatKing(addressa,uintw)viewreturns(uint){namReg.call.gas(1000000)("register","MyName");}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 32
column: 4
content: functionat(address_addr)viewreturns(uint){assembly{letsize:=extcodesize(_addr)extcodecopy(_addr,add(o_code,0x20),0,size)}}

SOLIDITY_VISIBILITY :7
SOLIDITY_DEPRECATED_CONSTRUCTIONS :1
SOLIDITY_PRAGMAS_VERSION :1
SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN :7
SOLIDITY_UPGRADE_TO_050 :1
SOLIDITY_USING_INLINE_ASSEMBLY :1
SOLIDITY_UNCHECKED_CALL :2
SOLIDITY_SHOULD_NOT_BE_VIEW :6

```
