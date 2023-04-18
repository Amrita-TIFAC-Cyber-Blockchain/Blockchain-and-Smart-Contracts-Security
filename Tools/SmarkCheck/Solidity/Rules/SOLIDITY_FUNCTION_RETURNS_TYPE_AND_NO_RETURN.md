# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_FUNCTION_RETURNS_TYPE_AND_NO_RETURN

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