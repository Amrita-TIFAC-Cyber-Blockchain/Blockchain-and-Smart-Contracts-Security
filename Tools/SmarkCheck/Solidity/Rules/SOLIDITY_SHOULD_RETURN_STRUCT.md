# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_SHOULD_RETURN_STRUCT
### Rule Description
<p>
Consider using struct instead of multiple return values for <code>internal</code> or <code>private</code> functions. It can improve code readability.
</p>

### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-7d54ca-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
sourceUnit
                        [
                            not(pragmaDirective//versionLiteral
                                [matches(text()[1], "^0\.\s*[5-9]\s*\.|^0\.\s*[0-9]{2,}\s*\.|^[1-9]")])
                            and not(pragmaDirective/pragmaExperimental//stringLiteral
                                [text()[1] = "ABIEncoderV2"])
                        ]
                        //functionDefinition[visibleType[matches(text()[1], "internal|private")]]
                        /returnsParameters/parameterList[count(parameter) > 3]
```

![](https://img.shields.io/badge/Pattern_ID-83hf3l-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
sourceUnit
                        [
                            pragmaDirective//versionLiteral
                                [matches(text()[1], "^0\.\s*[5-9]\s*\.|^0\.\s*[0-9]{2,}\s*\.|^[1-9]")]
                            or pragmaDirective/pragmaExperimental//stringLiteral
                                [text()[1] = "ABIEncoderV2"]
                        ]
                        //functionDefinition/returnsParameters/parameterList[count(parameter) > 3]
```

![](https://img.shields.io/badge/Pattern_ID-e5gh7l-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
expression[text()[1] = "="]
                        [expression[1]/tupleExpression[count(expression) > 3]]
                        [expression[2]/functionCall]
```

### Sample Code

```
pragma solidity 0.4.24;

contract C {
    // <yes> <report> SOLIDITY_SHOULD_RETURN_STRUCT 7d54ca
    function f1() internal returns(uint a, uint b, uint c, uint d) {
        a = 1;
        b = 2;
        c = 3;
        d = 4;
    }
    // <yes> <report> SOLIDITY_SHOULD_RETURN_STRUCT 7d54ca
    function f2() private returns(uint a, uint b, uint c, uint d) {
        a = 1;
        b = 2;
        c = 3;
        d = 4;
    }

    function f5() external returns(uint a, uint b, uint c, uint d) {
        a = 1;
        b = 2;
        c = 3;
        d = 4;
    }

    function f6() returns(uint a) {
        a = 1;
    }

    function f7() public returns(uint a, uint b, uint c, uint d) {
        a = 1;
        b = 2;
        c = 3;
        d = 4;
    }

    function f8() public returns(uint a, uint b) {
        (a, b) = f7();
    }

    function f9() public returns(uint a, uint b, uint c, uint d) {
    // <yes> <report> SOLIDITY_SHOULD_RETURN_STRUCT e5gh7l
        (a, b, c, d) = f2();
    }

    function f10() public returns(uint a) {
        (a, , , ) = f2();
    }
}
```

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/3600fc939d721a465259258985b48432/e0c31089dc5266ebbfcbd0ee79b07d08b98fe084) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_


### Code Result

```
SOLIDITY_SHOULD_RETURN_STRUCT
patternId: 7d54ca
severity: 1
line: 5
column: 34
content: (uinta,uintb,uintc,uintd)

ruleId: SOLIDITY_SHOULD_RETURN_STRUCT
patternId: 7d54ca
severity: 1
line: 12
column: 33
content: (uinta,uintb,uintc,uintd)

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 26
column: 4
content: functionf6()returns(uinta){a=1;}

SOLIDITY_VISIBILITY :1
SOLIDITY_SHOULD_RETURN_STRUCT :2

```
