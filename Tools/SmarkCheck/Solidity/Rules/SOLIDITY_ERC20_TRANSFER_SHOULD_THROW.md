# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_ERC20_TRANSFER_SHOULD_THROW

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