# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_VAR
### Rule Description
<p>
    Solidity supports type inference: the type of <code>i</code> in <code>var i = 42;</code> is the smallest integer type sufficient to store the right-hand side value (<code>uint8</code>). Consider a common for-loop pattern:
</p>
<pre>
<code>
for (var i = 0; i < array.length; i++) { /* ... */ }
</code>
</pre>
<p>
The type of <code>i</code> is inferred to <code>uint8</code>. If <code>array.length</code> is bigger than 255, an
overflow will occur. Explicitly define the type when declaring integer variables:
</p>
<pre>
<code>
for (uint256 i = 0; i < array.length; i++) { /* ... */ }
</code>
</pre>

### Solidity-Rules

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

### Code Result

```
ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: d3j11j
severity: 1
line: 6
column: 8
content: for(vari=0;i<a.length;i++){a[i]=i;}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: d3j11j
severity: 1
line: 9
column: 8
content: for(uint16i=0;i<a.length;i++){a[i]=i;}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: d3j11j
severity: 1
line: 16
column: 8
content: for(vari=minIdx;i<a.length;i++){a[i]=i;}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 6
column: 8
content: for(vari=0;i<a.length;i++){a[i]=i;}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 9
column: 8
content: for(uint16i=0;i<a.length;i++){a[i]=i;}

ruleId: SOLIDITY_PRAGMAS_VERSION
patternId: 23fc32
severity: 1
line: 1
column: 16
content: ^

ruleId: SOLIDITY_VAR
patternId: d28aa7
severity: 2
line: 6
column: 13
content: vari=0

ruleId: SOLIDITY_VAR
patternId: d28aa7
severity: 2
line: 15
column: 8
content: varminIdx=0

ruleId: SOLIDITY_VAR
patternId: f77619
severity: 1
line: 16
column: 13
content: vari=minIdx

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 4
column: 4
content: functionfoo1(){for(vari=0;i<a.length;i++){a[i]=i;}}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 8
column: 4
content: functionfoo2(){for(uint16i=0;i<a.length;i++){a[i]=i;}}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 11
column: 4
content: functionfoo3(){vara;varminIdx=0;for(vari=minIdx;i<a.length;i++){a[i]=i;}}

SOLIDITY_VISIBILITY :3
SOLIDITY_PRAGMAS_VERSION :1
SOLIDITY_VAR :3
SOLIDITY_EXTRA_GAS_IN_LOOPS :3
SOLIDITY_GAS_LIMIT_IN_LOOPS :2

```
