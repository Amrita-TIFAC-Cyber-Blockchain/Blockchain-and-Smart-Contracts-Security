# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_EXTRA_GAS_IN_LOOPS

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