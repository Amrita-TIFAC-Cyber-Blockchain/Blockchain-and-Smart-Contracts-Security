# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_UPGRADE_TO_050

### Rule Description
<p>
    Prepare your code for Solidity 0.5.0 release.
</p>

### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-83k1no-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
functionCall
                        [functionName/identifier[text()[1] = "call"]]
                        [callArguments/tupleExpression[count(expression) != 1]]
```

![](https://img.shields.io/badge/Pattern_ID-901eae-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
functionCall
                        [functionName/identifier[text()[1] = "keccak256"]]
                        [callArguments/tupleExpression[count(expression) > 1]]
```

![](https://img.shields.io/badge/Pattern_ID-91h3sa-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
		functionFallBackDefinition/visibleType[text()[1] != "external"]
		
```

![](https://img.shields.io/badge/Pattern_ID-341gim-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
		functionDefinition
                        [not(visibleType) or visibleType[text()[1] != "external"]]
                        parameter
                            [
                                typeName[text()[1] = "[]"]
                                or typeName/elementaryTypeName
                                    [text()[1] = "bytes" or text()[1] = "string"]
                                or typeName//identifier
                                    [text()[1]
                                        = ancestor::contractDefinition//structDefinition/identifier/text()[1]
                                    ]
                            ]
                            [not(storageLocation)]
		
```
![](https://img.shields.io/badge/Pattern_ID-441gim-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
		functionDefinition
                        variableDeclaration
                            [
                                typeName[text()[1] = "[]"]
                                or typeName/elementaryTypeName
                                    [text()[1] = "bytes" or text()[1] = "string"]
                                or typeName//identifier
                                    [text()[1]
                                        = ancestor::contractDefinition//structDefinition/identifier/text()[1]
                                    ]
                            ]
                            [not(storageLocation)]
		
```


### Sample Code

```
pragma solidity 0.4.24;

contract UpgradeTo050_1 {
    // <yes> <report> SOLIDITY_UPGRADE_TO_050 341gim
    function call(address token, bytes memory a, bytes b) public {
        // <yes> <report> SOLIDITY_UPGRADE_TO_050 83k1no
        address(token).call();
        // <yes> <report> SOLIDITY_UPGRADE_TO_050 83k1no
        token.call();
        // <yes> <report> SOLIDITY_UPGRADE_TO_050 83k1no
        token.call(a,b);
        token.call(2+2);
        token.call(abi.encodePacked(a, b));
        // <yes> <report> SOLIDITY_UPGRADE_TO_050 83k1no
        address(token).call(a,b);
        // <yes> <report> SOLIDITY_UPGRADE_TO_050 901eae
        bytes32 ab = keccak256(a, b);
        ab = keccak256(abi.encodePacked(a, b));
    }
    // <yes> <report> SOLIDITY_UPGRADE_TO_050 91h3sa
    function () private {
    }
}

contract UpgradeTo050_2 {
    struct User {
        uint a;
    }
    function numberZero(uint[] memory a) public {
    }
    function numberOne(uint[] storage a) internal {
    }
    // <yes> <report> SOLIDITY_UPGRADE_TO_050 341gim
    function numberTwo(uint[] a) public {
    }
    // <yes> <report> SOLIDITY_UPGRADE_TO_050 341gim
    function numberTwo_1(uint[] a) {
    }
    // <yes> <report> SOLIDITY_UPGRADE_TO_050 341gim <yes> <report> SOLIDITY_UPGRADE_TO_050 341gim
    function numberTwo0(bytes a, string b) public {
    }
    // <yes> <report> SOLIDITY_UPGRADE_TO_050 341gim
    function numberTwo1() public returns(uint[] a) {
    }
    // <yes> <report> SOLIDITY_UPGRADE_TO_050 341gim
    function numberTwo1_1() returns(uint[] a) {
    }
    function numberTwo2(User memory a) internal {
    }
    // <yes> <report> SOLIDITY_UPGRADE_TO_050 341gim
    function numberTwo3(User a) internal {
    }
    // <yes> <report> SOLIDITY_UPGRADE_TO_050 341gim
    function numberTwo3_1(User a) {
    }
    function numberThree(uint[] a) external {
    }
    // <yes> <report> SOLIDITY_UPGRADE_TO_050 91h3sa
    function () internal {
    }
}

contract UpgradeTo050_3 {
    uint[] intArray;
    function numberOne() external{
        // <yes> <report> SOLIDITY_UPGRADE_TO_050 441gim
        uint[] a;
        uint[] storage b = intArray;
        uint[] memory c = intArray;

    }
    function () external {
    }
}


contract UpgradeTo050_4 {
    struct User {
        uint a;
    }
    User userStruct;
    function numberOne() {
        // <yes> <report> SOLIDITY_UPGRADE_TO_050 441gim
        User a;
        User storage b = userStruct;
        User memory c = userStruct;

    }
    // <yes> <report> SOLIDITY_UPGRADE_TO_050 91h3sa
    function () public {
    }
}
```
### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/d3679a6b77032e9816ab0cb2e50a1a00/3551c5a0da19323a094e99020b703b17206691b2) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_

### Code Result

```
SOLIDITY_UPGRADE_TO_050.sol
jar:file:/C:/Users/Pothuri%20Harika/AppData/Roaming/npm/node_modules/@smartdec/smartcheck/jdeploy-bundle/smartcheck-2.0-jar-with-dependencies.jar!/solidity-rules.xmlruleId: SOLIDITY_CALL_WITHOUT_DATA
patternId: om991k
severity: 2
line: 7
column: 23
content: call()

ruleId: SOLIDITY_CALL_WITHOUT_DATA
patternId: om991k
severity: 2
line: 9
column: 14
content: call()

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 58bdd3
severity: 1
line: 43
column: 4
content: functionnumberTwo1()publicreturns(uint[]a){}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 58bdd3
severity: 1
line: 46
column: 4
content: functionnumberTwo1_1()returns(uint[]a){}

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 7
column: 23
content: call()

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 9
column: 14
content: call()

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 11
column: 14
content: call(a,b)

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 12
column: 14
content: call(2+2)

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 13
column: 14
content: call(abi.encodePacked(a,b))

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 15
column: 23
content: call(a,b)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 7
column: 23
content: call()

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 9
column: 14
content: call()

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 11
column: 14
content: call(a,b)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 15
column: 23
content: call(a,b)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 901eae
severity: 1
line: 17
column: 21
content: keccak256(a,b)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 91h3sa
severity: 1
line: 21
column: 16
content: private

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 91h3sa
severity: 1
line: 59
column: 16
content: internal

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 91h3sa
severity: 1
line: 90
column: 16
content: public

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 5
column: 49
content: bytesb

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 34
column: 23
content: uint[]a

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 40
column: 24
content: bytesa

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 40
column: 33
content: stringb

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 43
column: 41
content: uint[]a

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 51
column: 24
content: Usera

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 441gim
severity: 1
line: 67
column: 8
content: uint[]a

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 441gim
severity: 1
line: 84
column: 8
content: Usera

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 37
column: 4
content: functionnumberTwo_1(uint[]a){}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 46
column: 4
content: functionnumberTwo1_1()returns(uint[]a){}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 54
column: 4
content: functionnumberTwo3_1(Usera){}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 82
column: 4
content: functionnumberOne(){Usera;Userstorageb=userStruct;Usermemoryc=userStruct;}

ruleId: SOLIDITY_VISIBILITY
patternId: d67c21
severity: 1
line: 21
column: 16
content: private

ruleId: SOLIDITY_VISIBILITY
patternId: d67c21
severity: 1
line: 59
column: 16
content: internal

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 64
column: 4
content: uint[]intArray;

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 81
column: 4
content: UseruserStruct;

SOLIDITY_VISIBILITY :8
SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN :2
SOLIDITY_UPGRADE_TO_050 :16
SOLIDITY_UNCHECKED_CALL :6
SOLIDITY_CALL_WITHOUT_DATA :2
```
