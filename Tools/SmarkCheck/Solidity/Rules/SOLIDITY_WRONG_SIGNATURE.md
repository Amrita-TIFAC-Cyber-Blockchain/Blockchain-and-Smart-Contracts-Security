# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_WRONG_SIGNATURE
### Rule Description
<p>
    In Solidity, the function signature is defined as the canonical expression of the basic prototype without data location specifier, i.e. the function name with the parenthesised list of parameter types. Parameter types are split by a single comma - no spaces are used. This means one should use <code>uint256</code> and <code>int256</code> instead of <code>uint</code> or <code>int</code>.
</p>

### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-ui25n6-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
functionCall
                        [callArguments//primaryExpression
                            [
                                contains(stringLiteral, "uint,")
                                or contains(stringLiteral, "int,")
                                or contains(stringLiteral, "uint)")
                                or contains(stringLiteral, "int)")
                                or contains(stringLiteral, "uint[")
                                or contains(stringLiteral, "int[")
                            ]
                        ]
                        [callArguments/tupleExpression/expression[1]
                            [typeConversion[typeName/elementaryTypeName[text()[1] = "bytes4"]]]
                            [//functionCall/functionName/identifier[matches(text()[1], "^sha3$|^keccak256$")]]
                        ]
```

![](https://img.shields.io/badge/Pattern_ID-rec155-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
functionCall/callArguments
                        [tupleExpression/expression
                            [expression/primaryExpression/identifier[text()[1] = "abi"]]
                            [functionCall/functionName/identifier[text()[1] = "encodeWithSignature"]]
                            [
                                functionCall//primaryExpression
                                    [
                                        contains(stringLiteral, "uint)")
                                        or contains(stringLiteral, "int)")
                                        or contains(stringLiteral, "uint,")
                                        or contains(stringLiteral, "int,")
                                        or contains(stringLiteral, "uint[")
                                        or contains(stringLiteral, "int[")
                                    ]
                            ]
                        ]
```

### Sample Code

```
pragma solidity 0.4.25;

contract A {

    function foo1(address _spender, uint _value) public returns (bool success) {
        // <yes> <report> SOLIDITY_WRONG_SIGNATURE ui25n6
        require(_spender.call.value(10).gas(11)(bytes4(bytes32(sha3("receiveApproval(address,uint)"))), msg.sender, _value));
        return true;
    }

    function foo2(address _spender, int _value) public returns (bool success) {
        // <yes> <report> SOLIDITY_WRONG_SIGNATURE ui25n6
        require(_spender.call(bytes4(bytes32(keccak256("receiveApproval(address,int,address)"))), msg.sender, _value, this));
        return true;
    }

    function foo3(address _spender, uint256 _value) public returns (bool success) {
        require(_spender.call(bytes4(bytes32(sha3("receiveApproval(address,uint256,address)"))), msg.sender, _value, this));
        return true;
    }

    function foo4(address _spender, int256 _value) public returns (bool success) {
        require(_spender.call(bytes4(bytes32(keccak256("receiveApproval(address,int256)"))), msg.sender, _value));
        return true;
    }

    function foo5(address _spender, uint _value ) public returns (bool success) {
        // <yes> <report> SOLIDITY_WRONG_SIGNATURE ui25n6
        return _spender.call.gas(11)(bytes4(sha3("receiveApproval(address,uint)")), msg.sender, _value);
    }

    function foo6(address _spender, int _value ) public returns (bool success) {
        // <yes> <report> SOLIDITY_WRONG_SIGNATURE ui25n6
        return _spender.call(bytes4(keccak256("receiveApproval(address,int, address)")), msg.sender, _value, this);
    }

    function foo7(address _spender, uint256 _value) public returns (bool success) {
        return _spender.call.value(10)(bytes4(sha3("receiveApproval(address,address)")), msg.sender, this);
    }

    function foo8(address _spender, uint _value) public returns (bool success) {
        // <yes> <report> SOLIDITY_WRONG_SIGNATURE rec155
        return _spender.call(abi.encodeWithSignature("receiveApproval(address,uint)"), msg.sender, _value);
    }

    function foo9(address _spender, int _value) public returns (bool success) {
        // <yes> <report> SOLIDITY_WRONG_SIGNATURE rec155
        return _spender.call(abi.encodeWithSignature("receiveApproval(address,int)"), msg.sender, _value);
    }

    function foo10(address _spender, uint _value) public returns (bool success) {
        // <yes> <report> SOLIDITY_WRONG_SIGNATURE rec155
        return _spender.call(abi.encodeWithSignature("receiveApproval(uint,address)"), _value, msg.sender);
    }

    function foo11(address _spender, uint256 _value) public returns (bool success) {
        return _spender.call(abi.encodeWithSignature("receiveApproval(uint256,address)"), _value, msg.sender);
    }

    function foo12(address _spender, int[] _value) public returns (bool success) {
        // <yes> <report> SOLIDITY_WRONG_SIGNATURE ui25n6
        require(_spender.call.value(10)(bytes4((sha3("receiveApproval(address,int[],address)"))), msg.sender, _value, this));
        return true;
    }

    function foo13(address _spender, uint[] _value) public returns (bool success) {
        // <yes> <report> SOLIDITY_WRONG_SIGNATURE ui25n6
        require(_spender.call(bytes4(bytes32(keccak256("receiveApproval(address,uint[],address)"))), msg.sender, _value, this));
        return true;
    }

    function foo14(address _spender, uint256[] _value) public returns (bool success) {
        require(_spender.call(bytes4(bytes32(keccak256("receiveApproval(address,uint256[],address)"))), msg.sender, _value, this));
        return true;
    }

    function foo11(address _spender, uint[] _value) public returns (bool success) {
        // <yes> <report> SOLIDITY_WRONG_SIGNATURE rec155
        return _spender.call(abi.encodeWithSignature("receiveApproval(uint[],address)"), _value, msg.sender);
    }

    function foo11(address _spender, int256[] _value) public returns (bool success) {
        return _spender.call(abi.encodeWithSignature("receiveApproval(int256[],address)"), _value, msg.sender);
    }
}
```

### Code Result

```
ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 187b5a
severity: 1
line: 7
column: 63
content: sha3

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 187b5a
severity: 1
line: 18
column: 45
content: sha3

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 187b5a
severity: 1
line: 29
column: 44
content: sha3

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 187b5a
severity: 1
line: 38
column: 46
content: sha3

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 187b5a
severity: 1
line: 62
column: 48
content: sha3

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 7
column: 25
content: call.value(10).gas(11)(bytes4(bytes32(sha3("receiveApproval(address,uint)"))),msg.sender,_value)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 13
column: 25
content: call(bytes4(bytes32(keccak256("receiveApproval(address,int,address)"))),msg.sender,_value,this)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 18
column: 25
content: call(bytes4(bytes32(sha3("receiveApproval(address,uint256,address)"))),msg.sender,_value,this)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 23
column: 25
content: call(bytes4(bytes32(keccak256("receiveApproval(address,int256)"))),msg.sender,_value)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 29
column: 24
content: call.gas(11)(bytes4(sha3("receiveApproval(address,uint)")),msg.sender,_value)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 34
column: 24
content: call(bytes4(keccak256("receiveApproval(address,int, address)")),msg.sender,_value,this)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 38
column: 24
content: call.value(10)(bytes4(sha3("receiveApproval(address,address)")),msg.sender,this)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 43
column: 24
content: call(abi.encodeWithSignature("receiveApproval(address,uint)"),msg.sender,_value)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 48
column: 24
content: call(abi.encodeWithSignature("receiveApproval(address,int)"),msg.sender,_value)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 53
column: 24
content: call(abi.encodeWithSignature("receiveApproval(uint,address)"),_value,msg.sender)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 57
column: 24
content: call(abi.encodeWithSignature("receiveApproval(uint256,address)"),_value,msg.sender)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 62
column: 25
content: call.value(10)(bytes4((sha3("receiveApproval(address,int[],address)"))),msg.sender,_value,this)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 68
column: 25
content: call(bytes4(bytes32(keccak256("receiveApproval(address,uint[],address)"))),msg.sender,_value,this)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 73
column: 25
content: call(bytes4(bytes32(keccak256("receiveApproval(address,uint256[],address)"))),msg.sender,_value,this)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 79
column: 24
content: call(abi.encodeWithSignature("receiveApproval(uint[],address)"),_value,msg.sender)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 83
column: 24
content: call(abi.encodeWithSignature("receiveApproval(int256[],address)"),_value,msg.sender)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 60
column: 37
content: int[]_value

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 66
column: 37
content: uint[]_value

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 72
column: 37
content: uint256[]_value

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 77
column: 37
content: uint[]_value

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 82
column: 37
content: int256[]_value

ruleId: SOLIDITY_WRONG_SIGNATURE
patternId: ui25n6
severity: 2
line: 7
column: 25
content: call.value(10).gas(11)(bytes4(bytes32(sha3("receiveApproval(address,uint)"))),msg.sender,_value)

ruleId: SOLIDITY_WRONG_SIGNATURE
patternId: ui25n6
severity: 2
line: 13
column: 25
content: call(bytes4(bytes32(keccak256("receiveApproval(address,int,address)"))),msg.sender,_value,this)

ruleId: SOLIDITY_WRONG_SIGNATURE
patternId: ui25n6
severity: 2
line: 29
column: 24
content: call.gas(11)(bytes4(sha3("receiveApproval(address,uint)")),msg.sender,_value)

ruleId: SOLIDITY_WRONG_SIGNATURE
patternId: ui25n6
severity: 2
line: 34
column: 24
content: call(bytes4(keccak256("receiveApproval(address,int, address)")),msg.sender,_value,this)

ruleId: SOLIDITY_WRONG_SIGNATURE
patternId: ui25n6
severity: 2
line: 62
column: 25
content: call.value(10)(bytes4((sha3("receiveApproval(address,int[],address)"))),msg.sender,_value,this)

ruleId: SOLIDITY_WRONG_SIGNATURE
patternId: ui25n6
severity: 2
line: 68
column: 25
content: call(bytes4(bytes32(keccak256("receiveApproval(address,uint[],address)"))),msg.sender,_value,this)

ruleId: SOLIDITY_WRONG_SIGNATURE
patternId: rec155
severity: 2
line: 43
column: 28
content: (abi.encodeWithSignature("receiveApproval(address,uint)"),msg.sender,_value)

ruleId: SOLIDITY_WRONG_SIGNATURE
patternId: rec155
severity: 2
line: 48
column: 28
content: (abi.encodeWithSignature("receiveApproval(address,int)"),msg.sender,_value)

ruleId: SOLIDITY_WRONG_SIGNATURE
patternId: rec155
severity: 2
line: 53
column: 28
content: (abi.encodeWithSignature("receiveApproval(uint,address)"),_value,msg.sender)

ruleId: SOLIDITY_WRONG_SIGNATURE
patternId: rec155
severity: 2
line: 79
column: 28
content: (abi.encodeWithSignature("receiveApproval(uint[],address)"),_value,msg.sender)

SOLIDITY_DEPRECATED_CONSTRUCTIONS :5
SOLIDITY_UPGRADE_TO_050 :21
SOLIDITY_WRONG_SIGNATURE :10

```
