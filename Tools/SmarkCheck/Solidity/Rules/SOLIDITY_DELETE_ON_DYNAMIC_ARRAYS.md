# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_DELETE_ON_DYNAMIC_ARRAYS
### Rule Description
Applying delete</code> or <code>.length = 0</code> to dynamically-sized storage arrays may lead to Out-of-Gas exception.

### Solidity-Rules
![](https://img.shields.io/badge/Pattern_ID-2ft3g5-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
 (
                        deleteStatement
                        | expression
                            [matches(text()[1], "^=$")]
                            [expression[2]//numberLiteral/decimalNumber/text()[1] = "0"]
                            /expression[1][matches(text()[1], "^\.length$")]
                    )
                        [
                            expression/primaryExpression/identifier
                                = ancestor::contractDefinition/contractPartDefinition/stateVariableDeclaration
                                    [
                                        typeName[text()[1] = "[]"] or
                                        typeName/elementaryTypeName
                                            [
                                                text()[1] = "bytes" or
                                                text()[1] = "string"
                                            ]
                                    ]/identifier
                        ]
```

![](https://img.shields.io/badge/Pattern_ID-6f23y5-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
(
                        deleteStatement
                        | expression
                            [matches(text()[1], "^=$")]
                            [expression[2]//numberLiteral/decimalNumber/text()[1] = "0"]
                            /expression[1][matches(text()[1], "^\.length$")]
                    )
                        [
                            expression/primaryExpression/identifier
                                = ancestor::functionDefinition/parameterList/parameter
                                    [storageLocation[text()[1] = "storage"]]/identifier
                        ]
```



### Sample Code

```
pragma solidity 0.4.24;

contract C {

    uint[] a;
    byte[] b;
    bytes c;
    string d;

    function storageArrays() external {
        // <yes> <report> SOLIDITY_DELETE_ON_DYNAMIC_ARRAYS  2ft3g5
        delete a;
        // <yes> <report> SOLIDITY_DELETE_ON_DYNAMIC_ARRAYS  2ft3g5
        delete b;
        // <yes> <report> SOLIDITY_DELETE_ON_DYNAMIC_ARRAYS  2ft3g5
        delete c;
        // <yes> <report> SOLIDITY_DELETE_ON_DYNAMIC_ARRAYS  2ft3g5
        delete d;
        // <yes> <report> SOLIDITY_DELETE_ON_DYNAMIC_ARRAYS  2ft3g5
        a.length = 0;
        // <yes> <report> SOLIDITY_DELETE_ON_DYNAMIC_ARRAYS  2ft3g5
        b.length = 0;
        // <yes> <report> SOLIDITY_DELETE_ON_DYNAMIC_ARRAYS  2ft3g5
        c.length = 0;
    }

    function referenceArrays(uint[] storage a3, byte[] storage b3, bytes storage c3, string storage d3) internal {
        // <yes> <report> SOLIDITY_DELETE_ON_DYNAMIC_ARRAYS  6f23y5
        delete a3;
        // <yes> <report> SOLIDITY_DELETE_ON_DYNAMIC_ARRAYS  6f23y5
        delete b3;
        // <yes> <report> SOLIDITY_DELETE_ON_DYNAMIC_ARRAYS  6f23y5
        delete c3;
        // <yes> <report> SOLIDITY_DELETE_ON_DYNAMIC_ARRAYS  6f23y5
        delete d3;
        // <yes> <report> SOLIDITY_DELETE_ON_DYNAMIC_ARRAYS  6f23y5
        a3.length = 0;
        // <yes> <report> SOLIDITY_DELETE_ON_DYNAMIC_ARRAYS  6f23y5
        b3.length = 0;
        // <yes> <report> SOLIDITY_DELETE_ON_DYNAMIC_ARRAYS  6f23y5
        c3.length = 0;
    }

    function argumentsArrays(uint[] memory a1, byte[] memory b1, bytes memory c1, string memory d1) public {
        delete a1;
        delete b1;
        delete c1;
        delete d1;
        a1.length = 0;
        b1.length = 0;
        c1.length = 0;
    }

    function memoryArrays() external {
        uint[] memory a2;
        byte[] memory b2;
        bytes memory c2;
        string memory d2;

        delete a2;
        delete b2;
        delete c2;
        delete d2;
        a2.length = 0;
        b2.length = 0;
        c2.length = 0;
    }
}
```

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/2cc55e88ecd6455c5e9114d6eaf3cf54/6a498ad2a5266bdcfe00f7decaa240b79851c1e5) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_

### Code Result

```
SOLIDITY_ARRAY_LENGTH_MANIPULATION
patternId: 872bdd
severity: 1
line: 20
column: 8
content: a.length=0

ruleId: SOLIDITY_ARRAY_LENGTH_MANIPULATION
patternId: 872bdd
severity: 1
line: 22
column: 8
content: b.length=0

ruleId: SOLIDITY_ARRAY_LENGTH_MANIPULATION
patternId: 872bdd
severity: 1
line: 24
column: 8
content: c.length=0

ruleId: SOLIDITY_ARRAY_LENGTH_MANIPULATION
patternId: 872bdd
severity: 1
line: 37
column: 8
content: a3.length=0

ruleId: SOLIDITY_ARRAY_LENGTH_MANIPULATION
patternId: 872bdd
severity: 1
line: 39
column: 8
content: b3.length=0

ruleId: SOLIDITY_ARRAY_LENGTH_MANIPULATION
patternId: 872bdd
severity: 1
line: 41
column: 8
content: c3.length=0

ruleId: SOLIDITY_ARRAY_LENGTH_MANIPULATION
patternId: 872bdd
severity: 1
line: 49
column: 8
content: a1.length=0

ruleId: SOLIDITY_ARRAY_LENGTH_MANIPULATION
patternId: 872bdd
severity: 1
line: 50
column: 8
content: b1.length=0

ruleId: SOLIDITY_ARRAY_LENGTH_MANIPULATION
patternId: 872bdd
severity: 1
line: 51
column: 8
content: c1.length=0

ruleId: SOLIDITY_ARRAY_LENGTH_MANIPULATION
patternId: 872bdd
severity: 1
line: 64
column: 8
content: a2.length=0

ruleId: SOLIDITY_ARRAY_LENGTH_MANIPULATION
patternId: 872bdd
severity: 1
line: 65
column: 8
content: b2.length=0

ruleId: SOLIDITY_ARRAY_LENGTH_MANIPULATION
patternId: 872bdd
severity: 1
line: 66
column: 8
content: c2.length=0

ruleId: SOLIDITY_BYTE_ARRAY_INSTEAD_BYTES
patternId: f13a9f
severity: 1
line: 6
column: 4
content: byte[]

ruleId: SOLIDITY_BYTE_ARRAY_INSTEAD_BYTES
patternId: f13a9f
severity: 1
line: 27
column: 48
content: byte[]

ruleId: SOLIDITY_BYTE_ARRAY_INSTEAD_BYTES
patternId: f13a9f
severity: 1
line: 44
column: 47
content: byte[]

ruleId: SOLIDITY_BYTE_ARRAY_INSTEAD_BYTES
patternId: f13a9f
severity: 1
line: 56
column: 8
content: byte[]

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 5
column: 4
content: uint[]a;

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 6
column: 4
content: byte[]b;

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 7
column: 4
content: bytesc;

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 8
column: 4
content: stringd;

SOLIDITY_VISIBILITY :4
SOLIDITY_ARRAY_LENGTH_MANIPULATION :12
SOLIDITY_BYTE_ARRAY_INSTEAD_BYTES :4

```
