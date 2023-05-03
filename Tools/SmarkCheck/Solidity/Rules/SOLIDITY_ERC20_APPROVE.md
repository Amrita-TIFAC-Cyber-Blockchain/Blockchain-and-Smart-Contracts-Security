# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_ERC20_APPROVE
### Rule Description
The <code>approve</code> function of ERC-20 is vulnerable. Using front-running attack one can spend approved tokens before change of <code>allowance</code> value.
</p>

### Solidity-Rules

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
### Code Result

```
SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 49bd2a
severity: 1
line: 10
column: 26
content: throw

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 49bd2a
severity: 1
line: 34
column: 29
content: throw

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 49bd2a
severity: 1
line: 45
column: 29
content: throw

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 49bd2a
severity: 1
line: 55
column: 29
content: throw

ruleId: SOLIDITY_ERC20_APPROVE
patternId: af782c
severity: 2
line: 5
column: 4
content: functionapprove(address_spender,uint_value)returns(boolsuccess){require(_value>10wei);returntrue;}

ruleId: SOLIDITY_ERC20_APPROVE
patternId: af782c
severity: 2
line: 17
column: 4
content: functionapprove(address_spender,uint_value)returns(boolsuccess){require(_value>10wei);returntrue;}

ruleId: SOLIDITY_ERC20_APPROVE
patternId: af782c
severity: 2
line: 29
column: 4
content: functionapprove(address_spender,uint_value)returns(boolsuccess){require(_value>10wei);returntrue;}

ruleId: SOLIDITY_ERC20_APPROVE
patternId: af782c
severity: 2
line: 40
column: 4
content: functionapprove(address_spender,uint_value)returns(boolsuccess){require(_value>10wei);returntrue;}

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 10
column: 5
content: if(_value<20wei)throw;

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 34
column: 8
content: if(_value<20wei)throw;

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 45
column: 8
content: if(_value<20wei)throw;

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 55
column: 8
content: if(_value<20wei)throw;

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 5
column: 4
content: functionapprove(address_spender,uint_value)returns(boolsuccess){require(_value>10wei);returntrue;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 9
column: 4
content: functiontransferFrom(address_spender,uint_value)returns(boolsuccess){if(_value<20wei)throw;returntrue;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 17
column: 4
content: functionapprove(address_spender,uint_value)returns(boolsuccess){require(_value>10wei);returntrue;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 29
column: 4
content: functionapprove(address_spender,uint_value)returns(boolsuccess){require(_value>10wei);returntrue;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 33
column: 4
content: functiontransferFrom(address_spender,uint_value)returns(boolsuccess){if(_value<20wei)throw;returntrue;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 40
column: 4
content: functionapprove(address_spender,uint_value)returns(boolsuccess){require(_value>10wei);returntrue;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 44
column: 4
content: functiontransferFrom(address_spender,uint_value)returns(boolsuccess){if(_value<20wei)throw;returntrue;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 50
column: 4
content: functionapprove(address_spender,uint_value)returns(boolsuccess){require(_value>10wei);returntrue;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 54
column: 4
content: functiontransferFrom(address_spender,uint_value)returns(boolsuccess){if(_value<20wei)throw;returntrue;}

SOLIDITY_VISIBILITY :9
SOLIDITY_DEPRECATED_CONSTRUCTIONS :4
SOLIDITY_REVERT_REQUIRE :4
SOLIDITY_ERC20_APPROVE :4

```
