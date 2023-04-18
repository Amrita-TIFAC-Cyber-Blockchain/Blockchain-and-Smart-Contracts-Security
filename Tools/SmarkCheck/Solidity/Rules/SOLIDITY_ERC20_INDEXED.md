# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_ERC20_INDEXED

![](https://img.shields.io/badge/Pattern_ID-ac081b-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
   <!-- looks for Transfer and Aproval events -->
                    //eventDefinition[identifier[text()[1] = "Transfer" or text()[1] = "Approval"]]
                    <!-- with unindexed address parameter -->
                        [
                            indexedParameterList/indexedParameter
                                [typeName/elementaryTypeName[text()[1] = "address"]]
                                [not(text()[1] = "indexed")]
                        ]
                    <!-- check that event has three parameters -->
                        [indexedParameterList[count(child::indexedParameter) = 3]
                    <!-- check that there are two address parameters in the event -->
                        [count(child::indexedParameter//elementaryTypeName[text()[1] = "address"]) = 2]
                    <!-- check that there is one uint256 parameter in the event -->
                        [count(child::indexedParameter//elementaryTypeName[text()[1] = "uint256"]) = 1]]
```


### Sample Code

```
pragma solidity 0.5.0;

contract TestToken1 is ERC20{
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    // <yes> <report> SOLIDITY_ERC20_INDEXED ac081b
    event Approval(address  _owner, address indexed _spender, uint256 _value);
    event Check(address  _owner, address indexed _spender, uint256 _value);
}

contract Test2 is ERC20Mintable{
    // <yes> <report> SOLIDITY_ERC20_INDEXED ac081b
    event Transfer(address  _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract TestToken3 is ERC20Pausable{
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    // <yes> <report> SOLIDITY_ERC20_INDEXED ac081b
    event Approval(address  _owner, address  _spender, uint256 _value);
}

contract Test4 is ERC20{
    // <yes> <report> SOLIDITY_ERC20_INDEXED ac081b
    event Transfer(address  _from, address  _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract Test5 is SafeERC20{
    // <yes> <report> SOLIDITY_ERC20_INDEXED ac081b
    event Transfer(address indexed _from, address  _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract TestToken5 is ERC20Burnable{
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract SendSomething1 {
    event Transfer(address indexed _from, uint256 _value);
}

contract SendSomething2 {
    event Transfer(address indexed _from, address indexed _to);
}

contract SendSomething3 {
    event Approval(address indexed _to);
}
```