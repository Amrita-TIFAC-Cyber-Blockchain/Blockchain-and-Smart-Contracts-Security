# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_ERC20_FUNCTIONS_ALWAYS_RETURN_FALSE

![](https://img.shields.io/badge/Pattern_ID-b180ca-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
//contractDefinition
                        [
                            identifier[matches(text()[1], "token|erc20", "i")]
                            or inheritanceSpecifier/userDefinedTypeName/identifier[matches(text()[1], "token|erc20", "i")]
                        ]
                    //functionDefinition
                        [block/statement]
                        [identifier[matches(text()[1], "^transfer$|^transferFrom$|^approve$")]]
                        [returnsParameters/parameterList/parameter/typeName/elementaryTypeName[matches(text()[1], "bool")]]
                        [not(block/statement//returnStatement)]
                        [count(returnsParameters/parameterList/parameter) = 1]
                        [
                            returnsParameters/parameterList/parameter/identifier
                                [not(text()[1]
                                    = ancestor::functionDefinition/block//expression
                                        [matches(text()[1], "=")]/expression[1]//identifier)
                                ]
                            or returnsParameters/parameterList/parameter[not(identifier)]
                        ]
```

### Sample Code

```
pragma solidity 0.4.24;

contract TestToken {
    // <yes> <report> SOLIDITY_ERC20_FUNCTIONS_ALWAYS_RETURN_FALSE b180ca
    function approve(address _spender, uint _value) returns (bool success) {
    	if (_value < 20 wei) throw;
    }
    // <yes> <report> SOLIDITY_ERC20_FUNCTIONS_ALWAYS_RETURN_FALSE b180ca
    function transferFrom(address _spender, uint _value) returns (bool) {
        require(_value > 10 wei);
    }
}
contract TestToken2 {
    function transferFrom(address _spender, uint _value) returns (bool success) {
        require(_value > 10 wei);
        success = true;
    }
}

contract TestToken3 {
    function transferFrom(address _spender, uint _value) returns (bool) {
        require(_value > 10 wei);
        return true;
    }
    function transfer(address _spender, uint _value) returns (bool success) {
    	if (_value < 20 wei) revert();
    	return false;
    }
    function transferTokens(address _spender, uint _value) returns (bool success) {
        if (_value < 20 wei) revert();
    }
    function approve(address _to, uint256 _value) returns (bool);
 }
```