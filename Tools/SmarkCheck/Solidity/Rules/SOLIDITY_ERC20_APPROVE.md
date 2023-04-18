# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_ERC20_APPROVE

![](https://img.shields.io/badge/Pattern_ID-af782c-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
contractDefinition
                        [
                            identifier[matches(text()[1], "token|erc20", "i")]
                            or inheritanceSpecifier/userDefinedTypeName/identifier[matches(text()[1], "token|erc20", "i")]
                        ]
                        //functionDefinition
                            [block/statement]
                            [identifier[matches(text()[1], "^approve$")]]
                            [not(
                                ancestor::contractDefinition//functionDefinition
                                [block/statement]
                                [identifier[matches(text()[1], "Approval$|Allowance$|Approve$")]]
                            )
                            ]
```

![](https://img.shields.io/badge/Pattern_ID-lsd05g-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
contractDefinition
                        [
                            identifier[matches(text()[1], "token|erc20", "i")]
                            or inheritanceSpecifier/userDefinedTypeName/identifier[matches(text()[1], "token|erc20", "i")]
                        ]
                        //functionDefinition
                            [block/statement]
                            [identifier[matches(text()[1], "^approve$")]]
                            [ancestor::contractDefinition//functionDefinition
                                [block/statement]
                                [identifier[matches(text()[1], "Approval$|Allowance$|Approve$")]]
                            ]
```



### Sample Code

```
pragma solidity 0.4.24;

contract Token {
// <yes> <report> SOLIDITY_ERC20_APPROVE af782c
    function approve(address _spender, uint _value) returns (bool success) {
    	require(_value > 10 wei);
    	return true;
    }
    function transferFrom(address _spender, uint _value) returns (bool success) {
    	if (_value < 20 wei) throw;
    	return true;
    }
}

contract TokenSafe {
    // <yes> <report> SOLIDITY_ERC20_APPROVE lsd05g
    function approve(address _spender, uint _value) returns (bool success) {
        require(_value > 10 wei);
        return true;
    }
    function increaseAllowance(address spender, uint256 addedValue) public returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].add(addedValue));
        return true;
    }
}

contract TestERC20new {
     // <yes> <report> SOLIDITY_ERC20_APPROVE af782c
    function approve(address _spender, uint _value) returns (bool success) {
        require(_value > 10 wei);
     	return true;
    }
    function transferFrom(address _spender, uint _value) returns (bool success) {
        if (_value < 20 wei) throw;
     	return true;
    }
}
contract New is Token {
// <yes> <report> SOLIDITY_ERC20_APPROVE af782c
    function approve(address _spender, uint _value) returns (bool success) {
        require(_value > 10 wei);
       	return true;
    }
    function transferFrom(address _spender, uint _value) returns (bool success) {
        if (_value < 20 wei) throw;
       	return true;
    }
}
contract New2 {
    function approve(address _spender, uint _value) returns (bool success) {
        require(_value > 10 wei);
       	return true;
    }
    function transferFrom(address _spender, uint _value) returns (bool success) {
        if (_value < 20 wei) throw;
       	return true;
    }
}
contract ERC20 {
    function approve(address spender, uint256 value) public returns (bool);
}
```