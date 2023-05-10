# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_REDUNDANT_FALLBACK_REJECT
### Rule Description
<p>
    The payment rejection fallback is redundant.
</p>
<p>
    Contracts should reject unexpected payments. Before Solidity 0.4.0, it was done manually:
</p>
<pre>
<code>
function () { revert(); }
</code>
</pre>
<p>
Starting from Solidity 0.4.0, contracts without a fallback function automatically
revert payments, making the code above redundant.
</p>

### Solidity-Rules

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

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/d80d293b48b3017a2df3a5ebdab3b2e5/95b3a55d434885f042b9be0ef0f664661e0a4e04) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_


### Code Result

```
SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 49bd2a
severity: 1
line: 6
column: 8
content: throw

ruleId: SOLIDITY_LOCKED_MONEY
patternId: 30281d
severity: 3
line: 3
column: 0
content: contractC1{function()payable{throw;}}

ruleId: SOLIDITY_LOCKED_MONEY
patternId: 30281d
severity: 3
line: 15
column: 0
content: contractC3{function()payable{if(msg.sender==address(0)){revert();}}}

ruleId: SOLIDITY_LOCKED_MONEY
patternId: 30281d
severity: 3
line: 22
column: 0
content: contractC4{addressa;function()payable{a=msg.sender;revert();}}

ruleId: SOLIDITY_REDUNDANT_FALLBACK_REJECT
patternId: b85a32
severity: 1
line: 5
column: 23
content: {throw;}

ruleId: SOLIDITY_REDUNDANT_FALLBACK_REJECT
patternId: b85a32
severity: 1
line: 11
column: 15
content: {revert();}

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 17
column: 8
content: if(msg.sender==address(0)){revert();}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 5
column: 4
content: function()payable{throw;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 11
column: 4
content: function(){revert();}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 16
column: 4
content: function()payable{if(msg.sender==address(0)){revert();}}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 24
column: 4
content: function()payable{a=msg.sender;revert();}

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 23
column: 4
content: addressa;

SOLIDITY_VISIBILITY :5
SOLIDITY_DEPRECATED_CONSTRUCTIONS :1
SOLIDITY_REVERT_REQUIRE :1
SOLIDITY_LOCKED_MONEY :3
SOLIDITY_REDUNDANT_FALLBACK_REJECT :2

```


