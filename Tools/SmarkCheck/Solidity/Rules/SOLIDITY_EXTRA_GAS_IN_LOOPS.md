# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_EXTRA_GAS_IN_LOOPS
### Rule Description
<p>
    State variable, <code>.balance</code>, or <code>.length</code> of non-memory array is used in the condition of <code>for</code> or <code>while</code> loop. In this case, every iteration of loop consumes extra gas.
</p>
### Solidity-Rules


![](https://img.shields.io/badge/Pattern_ID-d3j11j-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
forStatement
                        [
                            (condition | expression[2])/expression/expression[not(matches(text()[1], "^\.balance$|^\.length$"))]//identifier
                                = ancestor::contractDefinition//stateVariableDeclaration[not(constantType)]/identifier
                        ]
```

![](https://img.shields.io/badge/Pattern_ID-5f8g1j-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
//forStatement[(condition | expression[2])//expression[matches(text()[1], "^\.balance$")]]
```

![](https://img.shields.io/badge/Pattern_ID-v843m7-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
//forStatement
                        [   <!-- 2nd or 3rd part contains '.length' expression -->
                            (condition | expression[2])//expression
                                [matches(text()[1], "^\.length$")]
                                <!-- and array is neither public function argument -->
                                [
                                    not(expression//text()[1]
                                        = ancestor::functionDefinition
                                            [
                                                visibleType[matches(text()[1], "^public$")]
                                                or not(visibleType)
                                            ]//parameter/identifier/text()
                                    )
                                ]
                                <!-- nor internal or private function argument with memory visibility modifier -->
                                [
                                    not(expression//text()[1]
                                        = ancestor::functionDefinition
                                            [visibleType[matches(text()[1], "^private$|^internal$")]]
                                            //parameter[storageLocation/text() = "memory"]/identifier/text()
                                    )
                                ]
                                <!-- nor copied to local variable with memory visibility modifier -->
                                [
                                    not(expression//text()[1]
                                        = ancestor::functionDefinition
                                            //variableDeclaration[storageLocation/text() = "memory"]/identifier/text()
                                    )
                                ]
                        ]
```

![](https://img.shields.io/badge/Pattern_ID-1f6n9l-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
//whileStatement[condition//expression[matches(text()[1], "^\.balance$")]]
```

![](https://img.shields.io/badge/Pattern_ID-v94c8j-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
//whileStatement
                        [   <!-- condition contains '.length' expression -->
                            condition//expression
                                [matches(text()[1], "^\.length$")]
                                <!-- and array is neither public function argument -->
                                [
                                    not(expression//text()[1]
                                        = ancestor::functionDefinition
                                            [
                                                visibleType[matches(text()[1], "^public$")]
                                                or not(visibleType)
                                            ]//parameter/identifier/text()
                                    )
                                ]
                                <!-- nor internal or private function argument with memory visibility modifier -->
                                [
                                    not(expression//text()[1]
                                        = ancestor::functionDefinition
                                            [visibleType[matches(text()[1], "^private$|^internal$")]]
                                            //parameter[storageLocation/text() = "memory"]/identifier/text()
                                    )
                                ]
                                <!-- nor copied to local variable with memory visibility modifier -->
                                [
                                    not(expression//text()[1]
                                        = ancestor::functionDefinition
                                            //variableDeclaration[storageLocation/text() = "memory"]/identifier/text()
                                    )
                                ]
                        ]
```
### Sample Code

```
pragma solidity 0.4.24;

contract GasInLoops {

    function balanceFor() external view {
    // <yes> <report> SOLIDITY_EXTRA_GAS_IN_LOOPS 5f8g1j
        for (uint i = 0; i < address(this).balance; i++) {
        }
    }

    function balanceWhile() external view {
        uint i = 0;
        // <yes> <report> SOLIDITY_EXTRA_GAS_IN_LOOPS 1f6n9l
        while (i < address(this).balance) {
        }
    }

    function balanceMemoryFor() external view {
        uint y = address(this).balance;
        for (uint i = 0; i < y; i++) {
        }
    }

    uint[] xx = new uint[](100);

    function lengthStorageWhile() external view {
        uint i = 0;
    // <yes> <report> SOLIDITY_EXTRA_GAS_IN_LOOPS v94c8j
        while (i < xx.length) {
        }
    }

    function lengthMemoryWhile() external view {
        uint y = xx.length;
        uint i = 0;
        while (i < y) {
        }
    }

    uint x = 100;

    function variableStorageFor() external view {
    // <yes> <report> SOLIDITY_EXTRA_GAS_IN_LOOPS d3j11j
        for (uint i = 0; i < x; i++) {
        }
    }

    function variableStorageWhile() external view {
        // <yes> <report> SOLIDITY_EXTRA_GAS_IN_LOOPS k4o1l4
        while (i < x) {
        }
    }

    function variableMemoryFor() external view {
        uint y = x;
        for (uint i = 0; i < y; i++) {
        }
    }

    uint constant XXX = 100;

    function variableStorageConstFor() external view {
        for (uint i = 0; i < XXX; i++) {
        }
    }

    function parameterStorageFor(uint[] memory x) public view {
        // <yes> <report> SOLIDITY_EXTRA_GAS_IN_LOOPS v843m7
        for (uint i = 0; i < xx.length; i++) {
        }
    }

    function lengthStorageFor() public view {
        // <yes> <report> SOLIDITY_EXTRA_GAS_IN_LOOPS v843m7
        for (uint i = 0; i < xx.length; i++) {
        }
    }

    function parameterCalldataFor(uint[] calldata x) external view {
        uint[] memory local = x;
        for (uint i = 0; i < local.length; i++) {
        }
    }

    function parameterMemoryCalldataWhile(uint[] memory m) view {
        uint i = 0;

        while (i < m.length) {
        }
    }

    function parameterStorageWhile(uint[] memory x) public view {
        uint i = 0;
        // <yes> <report> SOLIDITY_EXTRA_GAS_IN_LOOPS v94c8j
        while (i < xx.length) {
        }
    }

    function lengthMemoryCalldataWhile(uint[] calldata x) external view {
        uint[] memory y = x;
        while (i < y.length) {
        }
    }

    function lengthStorageWhile(uint[] calldata x) external view {
        uint[] storage y;
        // <yes> <report> SOLIDITY_EXTRA_GAS_IN_LOOPS v94c8j
        while (i < y.length) {
        }
    }

}
```

### Code Result

```
SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: d3j11j
severity: 1
line: 7
column: 8
content: for(uinti=0;i<address(this).balance;i++){}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: d3j11j
severity: 1
line: 44
column: 8
content: for(uinti=0;i<x;i++){}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: d3j11j
severity: 1
line: 63
column: 8
content: for(uinti=0;i<XXX;i++){}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: d3j11j
severity: 1
line: 69
column: 8
content: for(uinti=0;i<xx.length;i++){}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: d3j11j
severity: 1
line: 75
column: 8
content: for(uinti=0;i<xx.length;i++){}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: d3j11j
severity: 1
line: 81
column: 8
content: for(uinti=0;i<local.length;i++){}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: k4o1l4
severity: 1
line: 14
column: 8
content: while(i<address(this).balance){}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: k4o1l4
severity: 1
line: 29
column: 8
content: while(i<xx.length){}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: k4o1l4
severity: 1
line: 50
column: 8
content: while(i<x){}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: k4o1l4
severity: 1
line: 88
column: 8
content: while(i<m.length){}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: k4o1l4
severity: 1
line: 95
column: 8
content: while(i<xx.length){}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: k4o1l4
severity: 1
line: 101
column: 8
content: while(i<y.length){}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: k4o1l4
severity: 1
line: 108
column: 8
content: while(i<y.length){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 69
column: 8
content: for(uinti=0;i<xx.length;i++){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 75
column: 8
content: for(uinti=0;i<xx.length;i++){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 81
column: 8
content: for(uinti=0;i<local.length;i++){}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: 17f23a
severity: 1
line: 14
column: 15
content: i<address(this).balance

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: 17f23a
severity: 1
line: 29
column: 15
content: i<xx.length

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: 17f23a
severity: 1
line: 36
column: 15
content: i<y

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: 17f23a
severity: 1
line: 50
column: 15
content: i<x

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: 17f23a
severity: 1
line: 88
column: 15
content: i<m.length

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: 17f23a
severity: 1
line: 95
column: 15
content: i<xx.length

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: 17f23a
severity: 1
line: 101
column: 15
content: i<y.length

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: 17f23a
severity: 1
line: 108
column: 15
content: i<y.length

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 85
column: 4
content: functionparameterMemoryCalldataWhile(uint[]memorym)view{uinti=0;while(i<m.length){}}

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 24
column: 4
content: uint[]xx=newuint[](100);

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 40
column: 4
content: uintx=100;

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 60
column: 4
content: uintconstantXXX=100;

SOLIDITY_VISIBILITY :4
SOLIDITY_EXTRA_GAS_IN_LOOPS :13
SOLIDITY_GAS_LIMIT_IN_LOOPS :11


```

