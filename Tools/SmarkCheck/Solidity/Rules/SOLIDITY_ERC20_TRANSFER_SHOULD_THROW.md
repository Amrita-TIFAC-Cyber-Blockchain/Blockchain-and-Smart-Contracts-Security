# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_ERC20_TRANSFER_SHOULD_THROW
### Rule Description
<p>
Functions of ERC-20 Token Standard should throw in special cases:
</p>
<ul>
    <li><code>transfer</code> should throw if the <code>_from</code> account balance does not have enough tokens to spend</li>
    <li><code>transferFrom</code> should throw unless the <code>_from</code> account has deliberately authorized the sender of the message via some mechanism</li>
</ul>
### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-550a42-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
contractDefinition
                    [
                        identifier[matches(text()[1], "token|erc20", "i")]
                        or inheritanceSpecifier/userDefinedTypeName/identifier[matches(text()[1], "token|erc20", "i")]
                    ]
                    //functionDefinition
                        [block/statement]
                        [identifier[matches(text()[1], "^transfer(From)?$")]]
                        [returnsParameters/parameterList/parameter/typeName/elementaryTypeName[matches(text()[1], "bool")]]
                        [count(descendant-or-self::*[functionCall]
                            | descendant-or-self::*[statement/throwRevertStatement]) = 0
                        ]
```

### Sample Code

```
pragma solidity 0.4.24;

interface ERC20 { function transfer(address to, uint value) public returns(bool succes); }

contract Token{
	// <yes> <report> SOLIDITY_ERC20_TRANSFER_SHOULD_THROW 550a42
	function transfer(uint256 _value) returns (bool success) {
		if (_value > 0) {
			return true;
		}
		else {return false;}
	}
}
contract Token2{	
	function transfer(address _token, uint _value) returns (bool success) {
		ERC20(_token).transfer(msg.sender, _value);
	}
	function transferFrom(uint _value) returns (bool success) {
		require(_value > 10 wei);
		return false;
	}
}
contract Token3 is Token2{
	function transferFrom(uint _value) returns (bool success) {
		if (_value < 20 wei) {
			revert();
		}
		return true;
	}
	function transfer(address _token, uint _value) returns (bool success) {
		return super.transfer(_token,_value);
	}
}
```

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/4ad9caab2b9399efcce232ae82d7dbb1/803e711642dc5333147ea15f9247f2a6a54aa224) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_


### Code Result

```
SOLIDITY_ERC20_FUNCTIONS_ALWAYS_RETURN_FALSE
patternId: b180ca
severity: 2
line: 15
column: 1
content: functiontransfer(address_token,uint_value)returns(boolsuccess){ERC20(_token).transfer(msg.sender,_value);}

ruleId: SOLIDITY_ERC20_TRANSFER_SHOULD_THROW
patternId: 550a42
severity: 1
line: 7
column: 1
content: functiontransfer(uint256_value)returns(boolsuccess){if(_value>0){returntrue;}else{returnfalse;}}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 58bdd3
severity: 1
line: 15
column: 1
content: functiontransfer(address_token,uint_value)returns(boolsuccess){ERC20(_token).transfer(msg.sender,_value);}

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 25
column: 2
content: if(_value<20wei){revert();}

ruleId: SOLIDITY_VISIBILITY
patternId: 23rt6g
severity: 1
line: 3
column: 60
content: public

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 7
column: 1
content: functiontransfer(uint256_value)returns(boolsuccess){if(_value>0){returntrue;}else{returnfalse;}}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 15
column: 1
content: functiontransfer(address_token,uint_value)returns(boolsuccess){ERC20(_token).transfer(msg.sender,_value);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 18
column: 1
content: functiontransferFrom(uint_value)returns(boolsuccess){require(_value>10wei);returnfalse;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 24
column: 1
content: functiontransferFrom(uint_value)returns(boolsuccess){if(_value<20wei){revert();}returntrue;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 30
column: 1
content: functiontransfer(address_token,uint_value)returns(boolsuccess){returnsuper.transfer(_token,_value);}

SOLIDITY_VISIBILITY :6
SOLIDITY_ERC20_FUNCTIONS_ALWAYS_RETURN_FALSE :1
SOLIDITY_REVERT_REQUIRE :1
SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN :1
SOLIDITY_ERC20_TRANSFER_SHOULD_THROW :1


```
