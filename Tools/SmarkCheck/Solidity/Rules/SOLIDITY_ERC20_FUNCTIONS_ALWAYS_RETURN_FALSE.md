# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_ERC20_FUNCTIONS_ALWAYS_RETURN_FALSE
### Rule Description
The <code>transfer</code>, <code>transferFrom</code> or <code>approve</code> functions do not return <code>true</code> for any values of input parameters.
### Solidity-Rules

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
### Code Result

```
SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 49bd2a
severity: 1
line: 6
column: 26
content: throw

ruleId: SOLIDITY_ERC20_APPROVE
patternId: af782c
severity: 2
line: 5
column: 4
content: functionapprove(address_spender,uint_value)returns(boolsuccess){if(_value<20wei)throw;}

ruleId: SOLIDITY_ERC20_FUNCTIONS_ALWAYS_RETURN_FALSE
patternId: b180ca
severity: 2
line: 5
column: 4
content: functionapprove(address_spender,uint_value)returns(boolsuccess){if(_value<20wei)throw;}

ruleId: SOLIDITY_ERC20_FUNCTIONS_ALWAYS_RETURN_FALSE
patternId: b180ca
severity: 2
line: 9
column: 4
content: functiontransferFrom(address_spender,uint_value)returns(bool){require(_value>10wei);}

ruleId: SOLIDITY_ERC20_FUNCTIONS_ALWAYS_RETURN_FALSE
patternId: b180ca
severity: 2
line: 29
column: 4
content: functiontransferTokens(address_spender,uint_value)returns(boolsuccess){if(_value<20wei)revert();}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 47acc2
severity: 1
line: 9
column: 4
content: functiontransferFrom(address_spender,uint_value)returns(bool){require(_value>10wei);}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 58bdd3
severity: 1
line: 5
column: 4
content: functionapprove(address_spender,uint_value)returns(boolsuccess){if(_value<20wei)throw;}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 58bdd3
severity: 1
line: 29
column: 4
content: functiontransferTokens(address_spender,uint_value)returns(boolsuccess){if(_value<20wei)revert();}

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 6
column: 5
content: if(_value<20wei)throw;

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 26
column: 5
content: if(_value<20wei)revert();

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 30
column: 8
content: if(_value<20wei)revert();

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 5
column: 4
content: functionapprove(address_spender,uint_value)returns(boolsuccess){if(_value<20wei)throw;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 9
column: 4
content: functiontransferFrom(address_spender,uint_value)returns(bool){require(_value>10wei);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 14
column: 4
content: functiontransferFrom(address_spender,uint_value)returns(boolsuccess){require(_value>10wei);success=true;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 21
column: 4
content: functiontransferFrom(address_spender,uint_value)returns(bool){require(_value>10wei);returntrue;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 25
column: 4
content: functiontransfer(address_spender,uint_value)returns(boolsuccess){if(_value<20wei)revert();returnfalse;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 29
column: 4
content: functiontransferTokens(address_spender,uint_value)returns(boolsuccess){if(_value<20wei)revert();}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 32
column: 4
content: functionapprove(address_to,uint256_value)returns(bool);

SOLIDITY_VISIBILITY :7
SOLIDITY_ERC20_FUNCTIONS_ALWAYS_RETURN_FALSE :3
SOLIDITY_DEPRECATED_CONSTRUCTIONS :1
SOLIDITY_REVERT_REQUIRE :3
SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN :3
SOLIDITY_ERC20_APPROVE :1

```
