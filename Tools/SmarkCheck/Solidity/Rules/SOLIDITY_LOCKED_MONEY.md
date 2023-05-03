# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_LOCKED_MONEY
### Rule Description
<p>
    Contracts programmed to receive ether should implement a way to withdraw it, i.e., call <code>transfer</code> (recommended), <code>send</code>, or <code>call.value</code> at least once.
</p>

### Solidity-Rules

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
### Code Result
```
SOLIDITY_CALL_WITHOUT_DATA
patternId: om991k
severity: 2
line: 48
column: 10
content: call.value(amount)()

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 27cb59
severity: 1
line: 6
column: 8
content: suicide

ruleId: SOLIDITY_LOCKED_MONEY
patternId: 30281d
severity: 3
line: 38
column: 0
content: contractBadMarketPlace1{functiondeposit()payable{}functionfoo(){}}

ruleId: SOLIDITY_LOCKED_MONEY
patternId: 30281d
severity: 3
line: 53
column: 0
content: contractBadMarketPlace2{function()payable{}}

ruleId: SOLIDITY_LOCKED_MONEY
patternId: 30281d
severity: 3
line: 58
column: 0
content: contractBadMarketPlace3{function()payable{}}

ruleId: SOLIDITY_LOCKED_MONEY
patternId: 30281d
severity: 3
line: 63
column: 0
content: contractGoodMarketPlace9{function()payableexternal{}functionfoo(addressa,bytescalldatadata)payableexternal{a.delegatecall(data);}}

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 48
column: 10
content: call.value(amount)()

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 66
column: 10
content: delegatecall(data)

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 83k1no
severity: 1
line: 48
column: 10
content: call.value(amount)()

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 12
column: 4
content: functionkill()payable{selfdestruct(msg.sender);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 21
column: 4
content: functionsomeComp()payable{if(x.balance<10&&myAddress.balance>=10)x.send(10);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 29
column: 4
content: functiondeposit(addressw){w.transfer(9);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 32
column: 4
content: functiondeposit1()payable{}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 33
column: 4
content: functionfoo(){a=0;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 39
column: 4
content: functiondeposit()payable{}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 40
column: 4
content: functionfoo(){}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 46
column: 4
content: functiondeposit()payable{}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 47
column: 4
content: functionfoo(uintamount)payable{s.call.value(amount)();}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 54
column: 5
content: function()payable{}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 59
column: 4
content: function()payable{}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 72
column: 4
content: functionfoo(){}

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 19
column: 4
content: addressx;

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 20
column: 4
content: addressmyAddress;

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 28
column: 4
content: uinta;

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 45
column: 4
content: addresss;

SOLIDITY_VISIBILITY :16
SOLIDITY_DEPRECATED_CONSTRUCTIONS :1
SOLIDITY_LOCKED_MONEY :4
SOLIDITY_UPGRADE_TO_050 :1
SOLIDITY_UNCHECKED_CALL :2
SOLIDITY_CALL_WITHOUT_DATA :1

```
