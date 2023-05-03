# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_GAS_LIMIT_IN_LOOPS
### Rule Description
<p>
    Ethereum is a very resource-constrained environment. Prices per computational step are orders of magnitude higher than with centralized providers. Moreover, Ethereum miners impose a limit on the total number of gas consumed in a block. If <code>array.length</code> is large enough, the function exceeds the block gas limit, and transactions calling it will never be confirmed:
</p>
<pre><code>
    for (uint256 i = 0; i < array.length ; i++) {
        cosltyFunc();
    }
</code></pre>
<p>
    This becomes a security issue, if an external actor influences <code>array.length</code>.
    E.g., if array enumerates all registered addresses, an adversary can register many addresses, causing the problem described above.
</p>
<p>
    Vulnerability type by SmartDec classification: <a href="https://github.com/smartdec/classification#gas-limitations">
    Infinite loops</a>.
</p>


### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-f6f853-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
//forStatement
                        [   <!-- i = 0; -->
                            expression[1][text()[1] = "="]/expression[2]//numberLiteral/decimalNumber[text()[1] = "0"]
                            <!-- uint i = 0; -->
                            or expression[1]/variableDeclaration[text()[1] = "="]/expression//numberLiteral/decimalNumber[text()[1] = "0"]
                            <!-- uint i; -->
                            or expression[1]/variableDeclaration[not(text()[1] = "=")]
                        ]
                        [   <!-- ".length" in condition and base is not in memory -->
                            condition/expression[matches(text()[1], "&lt;|&lt;=")]/expression[2][text()[1] = ".length"]/expression/primaryExpression/identifier
                                <!-- and array is neither public or external function argument -->
                                [not(text()[1] = ancestor::functionDefinition[visibleType[matches(text()[1], "^public$|^external$")] or not(visibleType)]//parameter/identifier/text())]
                                <!-- nor internal or private function argument with memory visibility modifier -->
                                [not(text()[1] = ancestor::functionDefinition[visibleType[matches(text()[1], "^private$|^internal$")]]//parameter[storageLocation/text() = "memory"]/identifier/text())]
                                <!-- nor copied to local variable with memory visibility modifier -->
                                [not(text()[1] = ancestor::functionDefinition//variableDeclaration[storageLocation/text() = "memory"]/identifier/text())]
                            <!-- may be a variable in condition and it is ... -->
                            or condition/expression[matches(text()[1], "&lt;|&lt; =")]/expression[2]/primaryExpression/identifier
                                [   <!-- new variable with non-memory array length -->
                                    text()[1] = (ancestor::functionDefinition//variableDeclaration[text()[1] = "="]
                                        [expression[text()[1] = ".length"]/expression/primaryExpression/identifier
                                            <!-- and array is neither public or external function argument -->
                                            [not(text()[1] = ancestor::functionDefinition[visibleType[matches(text()[1], "^public$|^external$")] or not(visibleType)]//parameter/identifier/text())]
                                            <!-- nor internal or private function argument with memory visibility modifier -->
                                            [not(text()[1] = ancestor::functionDefinition[visibleType[matches(text()[1], "^private$|^internal$")]]//parameter[storageLocation/text() = "memory"]/identifier/text())]
                                            <!-- nor copied to local variable with memory visibility modifier -->
                                            [not(text()[1] = ancestor::functionDefinition//variableDeclaration[storageLocation/text() = "memory"]/identifier/text())]
                                        ]/identifier/text()[1])
                                    <!-- or reused variable with non-memory array length -->
                                    or text()[1] = (ancestor::functionDefinition//expression[text()[1] = "="]
                                        [expression[2][text()[1] = ".length"]/expression/primaryExpression/identifier
                                            <!-- and array is neither public or external function argument -->
                                            [not(text()[1] = ancestor::functionDefinition[visibleType[matches(text()[1], "^public$|^external$")] or not(visibleType)]//parameter/identifier/text())]
                                            <!-- nor internal or private function argument with memory visibility modifier -->
                                            [not(text()[1] = ancestor::functionDefinition[visibleType[matches(text()[1], "^private$|^internal$")]]//parameter[storageLocation/text() = "memory"]/identifier/text())]
                                            <!-- nor copied to local variable with memory visibility modifier -->
                                            [not(text()[1] = ancestor::functionDefinition//variableDeclaration[storageLocation/text() = "memory"]/identifier/text())]
                                        ]/expression[1]//identifier/text()[1])
                                ]
                        ]
```

![](https://img.shields.io/badge/Pattern_ID-4b7do5-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
//forStatement
                        [   <!-- i = 0; -->
                            expression[1][text()[1] = "="]/expression[2]//numberLiteral/decimalNumber[text()[1] = "0"]
                            <!-- uint i = 0; -->
                            or expression[1]/variableDeclaration[text()[1] = "="]/expression//numberLiteral/decimalNumber[text()[1] = "0"]
                            <!-- uint i; -->
                            or expression[1]/variableDeclaration[not(text()[1] = "=")]
                        ]
                        [   <!-- ".length" in condition and base is in memory -->
                            condition/expression[matches(text()[1], "&lt;|&lt;=")]/expression[2][text()[1] = ".length"]/expression/primaryExpression/identifier
                                [   <!-- and array is either public or external function argument -->
                                    text()[1] = ancestor::functionDefinition[visibleType[matches(text()[1], "^public$|^external$")] or not(visibleType)]//parameter/identifier/text()
                                    <!-- or internal or private function argument with memory visibility modifier -->
                                    or text()[1] = ancestor::functionDefinition[visibleType[matches(text()[1], "^private$|^internal$")]]//parameter[storageLocation/text() = "memory"]/identifier/text()
                                    <!-- or copied to local variable with memory visibility modifier -->
                                    or text()[1] = ancestor::functionDefinition//variableDeclaration[storageLocation/text() = "memory"]/identifier/text()
                                ]
                            <!-- may be a variable in condition and it is ... -->
                            or condition/expression[matches(text()[1], "&lt;|&lt;=")]/expression[2]/primaryExpression/identifier
                                [   <!-- new variable with memory array length -->
                                    text()[1] = (ancestor::functionDefinition//variableDeclaration[text()[1] = "="]
                                        [expression[text()[1] = ".length"]/expression/primaryExpression/identifier
                                            [   <!-- and array is either public or external function argument -->
                                                text()[1] = ancestor::functionDefinition[visibleType[matches(text()[1], "^public$|^external$")] or not(visibleType)]//parameter/identifier/text()
                                                <!-- or internal or private function argument with memory visibility modifier -->
                                                or text()[1] = ancestor::functionDefinition[visibleType[matches(text()[1], "^private$|^internal$")]]//parameter[storageLocation/text() = "memory"]/identifier/text()
                                                <!-- or copied to local variable with memory visibility modifier -->
                                                or text()[1] = ancestor::functionDefinition//variableDeclaration[storageLocation/text() = "memory"]/identifier/text()
                                            ]
                                        ]/identifier/text()[1])
                                    <!-- or reused variable with memory array length -->
                                    or text()[1] = (ancestor::functionDefinition//expression[text()[1] = "="]
                                        [expression[2][text()[1] = ".length"]/expression/primaryExpression/identifier
                                            [   <!-- and array is either public or external function argument -->
                                                text()[1] = ancestor::functionDefinition[visibleType[matches(text()[1], "^public$|^external$")] or not(visibleType)]//parameter/identifier/text()
                                                <!-- or internal or private function argument with memory visibility modifier -->
                                                or text()[1] = ancestor::functionDefinition[visibleType[matches(text()[1], "^private$|^internal$")]]//parameter[storageLocation/text() = "memory"]/identifier/text()
                                                <!-- or copied to local variable with memory visibility modifier -->
                                                or text()[1] = ancestor::functionDefinition//variableDeclaration[storageLocation/text() = "memory"]/identifier/text()
                                            ]
                                        ]/expression[1]//identifier/text()[1])
                                ]
                        ]
```

![](https://img.shields.io/badge/Pattern_ID-12cf32-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
forStatement
                        [
                            (   <!-- either reused variable with .length in pre-condition -->
                                expression[1][text()[1] = "="]/expression[2][text()[1] = ".length"]/expression/primaryExpression/identifier
                                <!-- or new variable with .length in pre-condition -->
                                | expression[1]/variableDeclaration[text()[1] = "="]/expression[text()[1] = ".length"]/expression/primaryExpression/identifier
                            )
                            <!-- and array is neither public or external function argument -->
                            [not(text()[1] = ancestor::functionDefinition[visibleType[matches(text()[1], "^public$|^external$")] or not(visibleType)]//parameter/identifier/text())]
                            <!-- nor internal or private function argument with memory visibility modifier -->
                            [not(text()[1] = ancestor::functionDefinition[visibleType[matches(text()[1], "^private$|^internal$")]]//parameter[storageLocation/text() = "memory"]/identifier/text())]
                            <!-- nor copied to local variable with memory visibility modifier -->
                            [not(text()[1] = ancestor::functionDefinition//variableDeclaration[storageLocation/text() = "memory"]/identifier/text())]
                        ]
                        [condition/expression[matches(text()[1], "&gt;|&gt;=")]]
```

![](https://img.shields.io/badge/Pattern_ID-v5j3d9-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
//forStatement
                    [
                        (   <!-- either reused variable with .length in pre-condition -->
                            expression[1][text()[1] = "="]/expression[2][text()[1] = ".length"]/expression/primaryExpression/identifier
                            <!-- or new variable with .length in pre-condition -->
                            | expression[1]/variableDeclaration[text()[1] = "="]/expression[text()[1] = ".length"]/expression/primaryExpression/identifier
                        )
                        [   <!-- and array is either public or external function argument -->
                            text()[1] = ancestor::functionDefinition[visibleType[matches(text()[1], "^public$|^external$")] or not(visibleType)]//parameter/identifier/text()
                            <!-- or internal or private function argument with memory visibility modifier -->
                            or text()[1] = ancestor::functionDefinition[visibleType[matches(text()[1], "^private$|^internal$")]]//parameter[storageLocation/text() = "memory"]/identifier/text()
                            <!-- or copied to local variable with memory visibility modifier -->
                            or text()[1] = ancestor::functionDefinition//variableDeclaration[storageLocation/text() = "memory"]/identifier/text()
                        ]
                    ]
                    [condition/expression[matches(text()[1], "&gt;|&gt;=")]]
```

![](https://img.shields.io/badge/Pattern_ID-17f23a-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
 //whileStatement/condition
                        [
                            not(descendant-or-self::functionCall)
                            and not(expression/expression/primaryExpression/numberLiteral/decimalNumber)
                        ]
```

![](https://img.shields.io/badge/Pattern_ID-38f6c7-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
 //whileStatement[condition/descendant::functionCall]
```

### Sample Code

```
pragma solidity 0.4.24;

contract GasLimitInLoops {
    function foo() pure internal returns (uint) {
        return(100);
    }

    function testWhile() public {
        uint x=0;
        uint[] memory y;
        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS 38f6c7
        while (x < foo()) {
        }
        while (x > 100) {
        }
        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS 17f23a
        while (y[5] < x) {
        }
    }

    function testFor(address[] _addr, uint amount) public {

        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS 4b7do5
        for (uint i = 0; i < _addr.length; i++) {
        }

        uint n = _addr.length;
        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS 4b7do5
        for (i = 0; i < n; i++) {
        }

        uint m;
        m = _addr.length;
        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS 4b7do5
        for (i = 0; i < m; i++) {
        }

        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS 4b7do5
        for (uint k; k < _addr.length; k++) {
        }

        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS v5j3d9
        for (i = _addr.length; i > 0; i--) {
        }
        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS v5j3d9
        for (uint j = _addr.length; j > 0; j--) {
        }
    }

    address[] stor;

    function testForMemory(address[] memory mem) {

        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS 4b7do5
        for (uint i = 0; i < mem.length; i++) {
        }

        uint n = mem.length;
        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS 4b7do5
        for (i = 0; i < n; i++) {
        }

        uint m;
        m = mem.length;
        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS 4b7do5
        for (i = 0; i < m; i++) {
        }

        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS 4b7do5
        for (uint k; k < mem.length; k++) {
        }

        address[] memory mem2;

        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS 4b7do5
        for (i = 0; i < mem2.length; i++) {
        }

        uint n2 = mem2.length;
        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS 4b7do5
        for (i = 0; i < n2; i++) {
        }

        uint m2;
        m2 = mem2.length;
        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS 4b7do5
        for (i = 0; i < m2; i++) {
        }

        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS 4b7do5
        for (k = 0; k < mem2.length; k++) {
        }

        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS 12cf32
        for (uint j = stor.length; j > 0; j--) {
        }

        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS f6f853
        for (k = 0; k < stor.length; k++) {
        }

        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS v5j3d9
        for (i = mem.length; i > 0; i--) {
        }

        // <yes> <report> SOLIDITY_GAS_LIMIT_IN_LOOPS v5j3d9
        for (j = mem2.length; j > 0; j--) {
        }
    }
}
```

### Code Result

```
SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: d3j11j
severity: 1
line: 24
column: 8
content: for(uinti=0;i<_addr.length;i++){}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: d3j11j
severity: 1
line: 39
column: 8
content: for(uintk;k<_addr.length;k++){}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: d3j11j
severity: 1
line: 55
column: 8
content: for(uinti=0;i<mem.length;i++){}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: d3j11j
severity: 1
line: 70
column: 8
content: for(uintk;k<mem.length;k++){}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: d3j11j
severity: 1
line: 76
column: 8
content: for(i=0;i<mem2.length;i++){}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: d3j11j
severity: 1
line: 91
column: 8
content: for(k=0;k<mem2.length;k++){}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: d3j11j
severity: 1
line: 99
column: 8
content: for(k=0;k<stor.length;k++){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 24
column: 8
content: for(uinti=0;i<_addr.length;i++){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 29
column: 8
content: for(i=0;i<n;i++){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 35
column: 8
content: for(i=0;i<m;i++){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 39
column: 8
content: for(uintk;k<_addr.length;k++){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 55
column: 8
content: for(uinti=0;i<mem.length;i++){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 60
column: 8
content: for(i=0;i<n;i++){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 66
column: 8
content: for(i=0;i<m;i++){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 70
column: 8
content: for(uintk;k<mem.length;k++){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 76
column: 8
content: for(i=0;i<mem2.length;i++){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 81
column: 8
content: for(i=0;i<n2;i++){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 87
column: 8
content: for(i=0;i<m2;i++){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 91
column: 8
content: for(k=0;k<mem2.length;k++){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 99
column: 8
content: for(k=0;k<stor.length;k++){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: 12cf32
severity: 2
line: 43
column: 8
content: for(i=_addr.length;i>0;i--){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: 12cf32
severity: 2
line: 46
column: 8
content: for(uintj=_addr.length;j>0;j--){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: 12cf32
severity: 2
line: 95
column: 8
content: for(uintj=stor.length;j>0;j--){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: 12cf32
severity: 2
line: 103
column: 8
content: for(i=mem.length;i>0;i--){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: 12cf32
severity: 2
line: 107
column: 8
content: for(j=mem2.length;j>0;j--){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: 17f23a
severity: 1
line: 17
column: 15
content: y[5]<x

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: 38f6c7
severity: 2
line: 12
column: 8
content: while(x<foo()){}

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 21
column: 21
content: address[]_addr

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 52
column: 4
content: functiontestForMemory(address[]memorymem){for(uinti=0;i<mem.length;i++){}uintn=mem.length;for(i=0;i<n;i++){}uintm;m=mem.length;for(i=0;i<m;i++){}for(uintk;k<mem.length;k++){}address[]memorymem2;for(i=0;i<mem2.length;i++){}uintn2=mem2.length;for(i=0;i<n2;i++){}uintm2;m2=mem2.length;for(i=0;i<m2;i++){}for(k=0;k<mem2.length;k++){}for(uintj=stor.length;j>0;j--){}for(k=0;k<stor.length;k++){}for(i=mem.length;i>0;i--){}for(j=mem2.length;j>0;j--){}}

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 50
column: 4
content: address[]stor;

SOLIDITY_VISIBILITY :2
SOLIDITY_EXTRA_GAS_IN_LOOPS :7
SOLIDITY_UPGRADE_TO_050 :1
SOLIDITY_GAS_LIMIT_IN_LOOPS :20

```
