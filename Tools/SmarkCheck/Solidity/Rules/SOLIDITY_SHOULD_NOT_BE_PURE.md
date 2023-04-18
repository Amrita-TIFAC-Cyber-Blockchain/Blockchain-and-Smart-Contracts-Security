# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_SHOULD_NOT_BE_PURE

![](https://img.shields.io/badge/Pattern_ID-11314f-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
functionDefinition
                        [
                            stateMutability/pureType
                            and block/descendant-or-self::*
                                [   <!--Accessing <address>.balance: using .balance-->
                                    expression[matches(text()[1], "\.balance")]
                                    <!--Accessing any of the members of block, tx, msg (with the exception of msg.sig and msg.data)-->
                                    or environmentalVariable[matches(text()[1], "msg\.value|msg\.gas|msg\.sender|block\.timestamp|tx\.origin|block\.blockhash|block\.coinbase|block\.difficulty|block\.gaslimit|block\.number|block\.blockhash|block\.coinbase|tx\.gasprice")]
                                    <!--Using selfdestruct and it's alias suicide:-->
                                    or functionCall/functionName//identifier[matches(text()[1], "^selfdestruct$|^suicide$")]
                                    <!--Sending Ether via calls:-->
                                    or functionCall/functionName//identifier[matches(text()[1], "^send$|^transfer$")]
                                    <!--Using low-level calls:-->
                                    or functionCall/functionName//identifier[matches(text()[1], "^call$|^delegatecall$|^callcode$")]
                                    <!--Using inline assembly that contains certain opcodes:-->
                                    or inlineAssemblyStatement
                                ]
                        ]
```



### Sample Code

```
pragma solidity ^0.4.16;

contract C {
    address f;
// <yes> <report> SOLIDITY_SHOULD_NOT_BE_PURE 11314f
    function returnsenderbalance() pure returns (uint){
         return msg.sender.balance;
    }
// <yes> <report> SOLIDITY_SHOULD_NOT_BE_PURE 11314f
    function returnsenderbalance() pure returns (uint){
        if (f < this.balance) x.send(10);
        return t;
    }
// <yes> <report> SOLIDITY_SHOULD_NOT_BE_PURE 11314f
    function returnsenderbalance() pure returns (uint){
        y=msg.value;
        o=block.timestamp;
        return t;
    }
    // <yes> <report> SOLIDITY_SHOULD_NOT_BE_PURE 11314f
    function returnsenderbalance() pure returns (uint){
        y=msg.value;
        o=block.timestamp;
        selfdestruct(f);
        return t;
    }
    function returnsenderbalance() pure returns (uint){
        return t;
    }
    function test() pure public returns (string memory name) {
        name = type(Math).name;
    }
}
contract Math {
    function Mul(uint a, uint b) pure internal returns (uint) {
      uint c = a * b;
      //check result should not be other wise until a=0
      assert(a == 0 || c / a == b);
      return c;
    }
}
```