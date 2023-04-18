# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_ARRAY_LENGTH_MANIPULATION

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
