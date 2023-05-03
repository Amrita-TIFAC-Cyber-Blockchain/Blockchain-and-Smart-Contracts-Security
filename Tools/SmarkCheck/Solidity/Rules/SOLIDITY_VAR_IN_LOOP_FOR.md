# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_VAR_IN_LOOP_FOR
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


![](https://img.shields.io/badge/Pattern_ID-f176ab-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
forStatement
                        [expression[1]/varDeclaration]
                        [condition/expression/expression/primaryExpression
                            [numberLiteral/decimalNumber
                                [matches(text()[1], "^[0-9]+$")]
                                &gt; 255
                            ]
                        ]
                        [expression[2]/twoPlusMinusOperator/incrementOperator]
```

### Sample Code

```
pragma solidity ^0.4.11;

contract SolidityUncheckedSend {
    function unseatKing(address a, uint w) view returns (uint){
    // <yes> <report> SOLIDITY_VAR_IN_LOOP_FOR f176ab
        for (var i = 0; i < 257; i++) {
            a=0;
        }
        for (var i = 0; i < 4; i++) {
            a=0;
        }
        for (var i = 1000; i > 400; i--) {
            a=0;
        }
    }
}
```
### Code Result

```
ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 47acc2
severity: 1
line: 4
column: 4
content: functionunseatKing(addressa,uintw)viewreturns(uint){for(vari=0;i<257;i++){a=0;}for(vari=0;i<4;i++){a=0;}for(vari=1000;i>400;i--){a=0;}}

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
line: 9
column: 13
content: vari=0

ruleId: SOLIDITY_VAR
patternId: d28aa7
severity: 2
line: 12
column: 13
content: vari=1000

ruleId: SOLIDITY_VAR_IN_LOOP_FOR
patternId: f176ab
severity: 2
line: 6
column: 8
content: for(vari=0;i<257;i++){a=0;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 4
column: 4
content: functionunseatKing(addressa,uintw)viewreturns(uint){for(vari=0;i<257;i++){a=0;}for(vari=0;i<4;i++){a=0;}for(vari=1000;i>400;i--){a=0;}}

SOLIDITY_VISIBILITY :1
SOLIDITY_PRAGMAS_VERSION :1
SOLIDITY_VAR_IN_LOOP_FOR :1
SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN :1
SOLIDITY_VAR :3

```
