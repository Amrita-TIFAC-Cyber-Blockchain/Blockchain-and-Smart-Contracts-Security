# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_LOCKED_MONEY

![](https://img.shields.io/badge/Pattern_ID-30281d-gold) ![](https://img.shields.io/badge/Severity-3-brown) 

```

contractDefinition
                        [contractPartDefinition
                            [
                                functionDefinition/stateMutability/payableType
                                or functionFallBackDefinition/stateMutability/payableType
                            ]
                        ]
                        [not(contractPartDefinition/functionDefinition/block//functionCall/functionName//identifier
                            [matches(text()[1], "^suicide$|^selfdestruct$")])]
                        [not(contractPartDefinition/functionDefinition/block//functionCall/functionName//identifier
                            [matches(text()[1], "^transfer$|^send$")])]
                        [not(contractPartDefinition/functionDefinition/block//functionCall/functionName//identifier
                            [matches(text()[1], "^delegatecall$")])]
                        [not(contractPartDefinition/functionDefinition/block//functionCall/value)]
```

### Sample Code

```
pragma solidity 0.4.24;


contract GoodMarketPlace {
    function kill() public {
        suicide(msg.sender);
    }
}


contract GoodMarketPlace1 {
    function kill() payable {
        selfdestruct(msg.sender);
    }
}


contract GoodMarketPlace2 {
    address x;
    address myAddress;
    function someComp() payable{
        if (x.balance < 10 && myAddress.balance >= 10) x.send(10);
    }
}


contract GoodMarketPlace3 {
    uint a;
    function deposit(address w){
        w.transfer(9);
    }
    function deposit1() payable {}
    function foo() {a=0;}
}


// <yes> <report> SOLIDITY_LOCKED_MONEY 30281d
contract BadMarketPlace1 {
    function deposit() payable {}
    function foo() {}
}


contract GoodMarketPlace6 {
    address s;
    function deposit() payable {}
    function foo(uint amount) payable {
        s.call.value(amount)();
    }
}

// <yes> <report> SOLIDITY_LOCKED_MONEY 30281d
contract BadMarketPlace2 {
     function() payable {}
}

// <yes> <report> SOLIDITY_LOCKED_MONEY 30281d
contract BadMarketPlace3 {
    function() payable {}
}


contract GoodMarketPlace9 {
    function() payable external{}
    function foo(address a, bytes calldata data) payable external {
        a.delegatecall(data);
    }
}


library BadMarketPlaceLibrary {
    function foo() {}
}
```
