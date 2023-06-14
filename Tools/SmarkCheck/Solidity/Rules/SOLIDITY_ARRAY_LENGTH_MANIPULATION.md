# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)<br/> 
![](https://img.shields.io/badge/Tool-Silther-blue)


## SOLIDITY_ARRAY_LENGTH_MANIPULATION

### Rule Description
The length of the dynamic array is changed directly. In this case, the appearance of gigantic arrays is possible and it can lead to a storage overlap attack (collisions with other data in storage)

![](https://img.shields.io/badge/Pattern_ID-872bdd-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
expression
                        [expression[1][matches(text()[1], "\.length$")]]
                        [
                            matches(text()[1], "^=$")
                            or twoPlusMinusOperator/decrementOperator
                            or lvalueOperator
                                [
                                    mulLvalueOperator
                                    or minusLvalueOperator
                                    or plusLvalueOperator
                                    or divLvalueOperator
                                ]
                        ]
```

![](https://img.shields.io/badge/Pattern_ID-43ba1c-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
expression
                        [expression[1][matches(text()[1], "\.length$")]]
                        [twoPlusMinusOperator/incrementOperator]

```

### Sample Code

```
pragma solidity 0.4.24;

contract dataStorage {
    uint[] public data;

    function badPractice(uint[] _data) external {
        for(uint i = 0; i < _data.length; i++) {
        // <yes> <report> SOLIDITY_ARRAY_LENGTH_MANIPULATION 43ba1c
            data.length++;
            data[i]=_data[i];
        }
        // <yes> <report> SOLIDITY_ARRAY_LENGTH_MANIPULATION 872bdd
        data.length = 10;
        // <yes> <report> SOLIDITY_ARRAY_LENGTH_MANIPULATION 872bdd
        data.length--;
        // <yes> <report> SOLIDITY_ARRAY_LENGTH_MANIPULATION 872bdd
        data.length *= 2;
        // <yes> <report> SOLIDITY_ARRAY_LENGTH_MANIPULATION 872bdd
        data.length -= 2;
        // <yes> <report> SOLIDITY_ARRAY_LENGTH_MANIPULATION 872bdd
        data.length += 2;
        // <yes> <report> SOLIDITY_ARRAY_LENGTH_MANIPULATION 872bdd
        data.length /= 2;
    }

    function goodPractice(uint[] _data) external {
        for(uint i = 0; i < _data.length; i++) {
            data.push(_data[i]);
        }
        uint a;
        if(data.length == 10) {
            a = data.length;
            a /= data.length;
            a *= data.length;
            a += data.length;
            a -= data.length;
        }
    }
}
```

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/81c8aaed84fc1a81a4e516815d154ff8/9ac375f3666adf0df5bc8909269be03134ae4fa2) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_

### Code Result

```
SOLIDITY_ARRAY_LENGTH_MANIPULATION
patternId: 872bdd
severity: 1
line: 13
column: 8
content: data.length=10

ruleId: SOLIDITY_ARRAY_LENGTH_MANIPULATION
patternId: 872bdd
severity: 1
line: 15
column: 8
content: data.length--

ruleId: SOLIDITY_ARRAY_LENGTH_MANIPULATION
patternId: 872bdd
severity: 1
line: 17
column: 8
content: data.length*=2

ruleId: SOLIDITY_ARRAY_LENGTH_MANIPULATION
patternId: 872bdd
severity: 1
line: 19
column: 8
content: data.length-=2

ruleId: SOLIDITY_ARRAY_LENGTH_MANIPULATION
patternId: 872bdd
severity: 1
line: 21
column: 8
content: data.length+=2

ruleId: SOLIDITY_ARRAY_LENGTH_MANIPULATION
patternId: 872bdd
severity: 1
line: 23
column: 8
content: data.length/=2

ruleId: SOLIDITY_ARRAY_LENGTH_MANIPULATION
patternId: 43ba1c
severity: 1
line: 9
column: 12
content: data.length++

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: d3j11j
severity: 1
line: 7
column: 8
content: for(uinti=0;i<_data.length;i++){data.length++;data[i]=_data[i];}

ruleId: SOLIDITY_EXTRA_GAS_IN_LOOPS
patternId: d3j11j
severity: 1
line: 27
column: 8
content: for(uinti=0;i<_data.length;i++){data.push(_data[i]);}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 7
column: 8
content: for(uinti=0;i<_data.length;i++){data.length++;data[i]=_data[i];}

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: f6f853
severity: 2
line: 27
column: 8
content: for(uinti=0;i<_data.length;i++){data.push(_data[i]);}

SOLIDITY_ARRAY_LENGTH_MANIPULATION :7
SOLIDITY_EXTRA_GAS_IN_LOOPS :2
SOLIDITY_GAS_LIMIT_IN_LOOPS :2


```



### Silther Result

```
INFO:Detectors:
DataStorage.goodPractice(uint256[]) (SOLIDITY_ARRAY_LENGTH_MANIPULATION.sol#26-38) performs a multiplication on the result of a division:
        - a /= data.length (SOLIDITY_ARRAY_LENGTH_MANIPULATION.sol#33)
        - a *= data.length (SOLIDITY_ARRAY_LENGTH_MANIPULATION.sol#34)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#divide-before-multiply
INFO:Detectors:
Pragma version0.4.24 (SOLIDITY_ARRAY_LENGTH_MANIPULATION.sol#1) allows old versions
solc-0.4.24 is not recommended for deployment
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity
INFO:Detectors:
Parameter DataStorage.badPractice(uint256[])._data (SOLIDITY_ARRAY_LENGTH_MANIPULATION.sol#6) is not in mixedCase
Parameter DataStorage.goodPractice(uint256[])._data (SOLIDITY_ARRAY_LENGTH_MANIPULATION.sol#26) is not in mixedCase
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#conformance-to-solidity-naming-conventions
INFO:Slither:SOLIDITY_ARRAY_LENGTH_MANIPULATION.sol analyzed (1 contracts with 85 detectors), 5 result(s) found
```
