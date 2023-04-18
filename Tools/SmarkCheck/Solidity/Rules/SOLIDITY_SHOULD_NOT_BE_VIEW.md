# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_SHOULD_NOT_BE_VIEW

![](https://img.shields.io/badge/Pattern_ID-189abf-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
functionDefinition
                        [
                            stateMutability/viewType
                            and block/descendant-or-self::*
                                [   <!--Using selfdestruct and it's alias suicide:-->
                                    functionCall/functionName//identifier[matches(text()[1], "^selfdestruct$|^suicide$")]
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
pragma solidity ^0.4.11;

contract SolidityUncheckedSend {
// <yes> <report> SOLIDITY_SHOULD_NOT_BE_VIEW 189abf
    function unseatKing(address a, uint w) view returns (uint){
        selfdestruct(a);
        }

// <yes> <report> SOLIDITY_SHOULD_NOT_BE_VIEW 189abf
    function unseatKing(address a, uint w) view returns (uint){
        suicide(a);
        }

    // <yes> <report> SOLIDITY_SHOULD_NOT_BE_VIEW 189abf
    function unseatKing(address a, uint w) view returns (uint){
        x.transfer(10);
        }

    // <yes> <report> SOLIDITY_SHOULD_NOT_BE_VIEW 189abf
    function unseatKing(address a, uint w) view returns (uint){
        x.send(10);
        }

    function unseatKing(address a, uint w) returns (uint){
        x.job(10);
        }
    // <yes> <report> SOLIDITY_SHOULD_NOT_BE_VIEW 189abf
    function unseatKing(address a, uint w) view returns (uint){
        namReg.call.gas(1000000)("register", "MyName");
        }
        // <yes> <report> SOLIDITY_SHOULD_NOT_BE_VIEW 189abf
    function at(address _addr) view returns (uint) {
        assembly{
            let
            size := extcodesize(_addr)
            extcodecopy(_addr, add(o_code, 0x20), 0, size)
            }
        }
}
```