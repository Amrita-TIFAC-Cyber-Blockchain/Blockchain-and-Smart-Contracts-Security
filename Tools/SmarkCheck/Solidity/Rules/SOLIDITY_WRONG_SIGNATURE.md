# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_WRONG_SIGNATURE

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
