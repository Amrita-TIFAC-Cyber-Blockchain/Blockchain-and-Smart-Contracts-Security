# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_FUNCTION_RETURNS_TYPE_AND_NO_RETURN
### Rule Description
<p>Function doesn't initialize return value. As result default value will be returned.</p>

### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-47acc2-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
//functionDefinition
                    [block]
                    [returnsParameters/parameterList/parameter[not(identifier)]]
                    [
                        not(block/statement//returnStatement)
                        and not(block//assemblyCall[matches(text()[1], "^return\(")])
                    ]
```

![](https://img.shields.io/badge/Pattern_ID-58bdd3-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
//functionDefinition
                    [block]
                    [
                        not(block/statement//returnStatement)
                        and not(block//assemblyCall[matches(text()[1], "^return\(")])
                    ]
                    [returnsParameters/parameterList/parameter/identifier
                        [
                            not(text()[1]
                                = (ancestor::functionDefinition/block//expression
                                    [matches(text()[1], "=")]/expression[1]//identifier/text()[1]))
                            and not(text()[1]
                                = ancestor::functionDefinition/block
                                    //assemblyAssignment/assemblyIdentifierOrList//identifier/text()[1])
                        ]
                    ]
```



### Sample Code

```
pragma solidity 0.4.24;

contract C {
    // <yes> <report> SOLIDITY_FUNCTION_RETURNS_TYPE_AND_NO_RETURN 47acc2
    function remainBalanced1() public constant returns (uint256){
        uint a =1000;
    }

    function assemblyTest1() public constant returns (uint256){
        assembly {
            mstore(0, 100)
            return(0, 32)
        }
    }
    // <yes> <report> SOLIDITY_FUNCTION_RETURNS_TYPE_AND_NO_RETURN 47acc2
    function remainBalanced2() public constant returns (uint a, uint256){
        a =1000;
    }
    // <yes> <report> SOLIDITY_FUNCTION_RETURNS_TYPE_AND_NO_RETURN 58bdd3
    function execute(address _to, uint _value, bytes _data) returns (uint256 _r) {
        if (_to == address(0)) {
            revert();
        }
    }
    function assemblyTest2(address _to, uint _value, bytes _data) returns (uint256 _r) {
        assembly {
            _r := 100
        }
    }
    // <yes> <report> SOLIDITY_FUNCTION_RETURNS_TYPE_AND_NO_RETURN 58bdd3
    function execute1(address _to, uint _value, bytes _data) returns (uint256 _r) {
        _value = _r;
    }
    // <yes> <report> SOLIDITY_FUNCTION_RETURNS_TYPE_AND_NO_RETURN 58bdd3
    function execute2(address _to, uint _value, bytes _data) returns (bool flag, uint256 _r) {
        flag = true;
        _value = balanceOf(address(_r));
    }

    function balanceOf(address who)public view returns (uint256);

    function remainBalanced() public constant returns (uint256){
        return balanceOf(this);
    }

    function balance(address who)public view returns (uint256 _r);

    function execute3(address _to, uint _value, bytes _data) returns (uint256 _r) {
        _r = balanceOf(_to);
    }

    function execute4(address _to, uint _value, bytes _data) returns (uint256 _r) {
        return balanceOf(_to);
    }
}
```
### Code Result
```
SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 28fa69
severity: 1
line: 5
column: 4
content: functionremainBalanced1()publicconstantreturns(uint256){uinta=1000;}

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 28fa69
severity: 1
line: 9
column: 4
content: functionassemblyTest1()publicconstantreturns(uint256){assembly{mstore(0,100)return(0,32)}}

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 28fa69
severity: 1
line: 16
column: 4
content: functionremainBalanced2()publicconstantreturns(uinta,uint256){a=1000;}

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 28fa69
severity: 1
line: 42
column: 4
content: functionremainBalanced()publicconstantreturns(uint256){returnbalanceOf(this);}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 47acc2
severity: 1
line: 5
column: 4
content: functionremainBalanced1()publicconstantreturns(uint256){uinta=1000;}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 47acc2
severity: 1
line: 9
column: 4
content: functionassemblyTest1()publicconstantreturns(uint256){assembly{mstore(0,100)return(0,32)}}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 47acc2
severity: 1
line: 16
column: 4
content: functionremainBalanced2()publicconstantreturns(uinta,uint256){a=1000;}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 58bdd3
severity: 1
line: 20
column: 4
content: functionexecute(address_to,uint_value,bytes_data)returns(uint256_r){if(_to==address(0)){revert();}}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 58bdd3
severity: 1
line: 25
column: 4
content: functionassemblyTest2(address_to,uint_value,bytes_data)returns(uint256_r){assembly{_r:=100}}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 58bdd3
severity: 1
line: 31
column: 4
content: functionexecute1(address_to,uint_value,bytes_data)returns(uint256_r){_value=_r;}

ruleId: SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN
patternId: 58bdd3
severity: 1
line: 35
column: 4
content: functionexecute2(address_to,uint_value,bytes_data)returns(boolflag,uint256_r){flag=true;_value=balanceOf(address(_r));}

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 21
column: 8
content: if(_to==address(0)){revert();}

ruleId: SOLIDITY_USING_INLINE_ASSEMBLY
patternId: 109cd5
severity: 1
line: 10
column: 8
content: assembly{mstore(0,100)return(0,32)}

ruleId: SOLIDITY_USING_INLINE_ASSEMBLY
patternId: 109cd5
severity: 1
line: 26
column: 8
content: assembly{_r:=100}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 20
column: 4
content: functionexecute(address_to,uint_value,bytes_data)returns(uint256_r){if(_to==address(0)){revert();}}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 25
column: 4
content: functionassemblyTest2(address_to,uint_value,bytes_data)returns(uint256_r){assembly{_r:=100}}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 31
column: 4
content: functionexecute1(address_to,uint_value,bytes_data)returns(uint256_r){_value=_r;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 35
column: 4
content: functionexecute2(address_to,uint_value,bytes_data)returns(boolflag,uint256_r){flag=true;_value=balanceOf(address(_r));}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 48
column: 4
content: functionexecute3(address_to,uint_value,bytes_data)returns(uint256_r){_r=balanceOf(_to);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 52
column: 4
content: functionexecute4(address_to,uint_value,bytes_data)returns(uint256_r){returnbalanceOf(_to);}

SOLIDITY_VISIBILITY :6
SOLIDITY_DEPRECATED_CONSTRUCTIONS :4
SOLIDITY_REVERT_REQUIRE :1
SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN :7
SOLIDITY_USING_INLINE_ASSEMBLY :2

```
