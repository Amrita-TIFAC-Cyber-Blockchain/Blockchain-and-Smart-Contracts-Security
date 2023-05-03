# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_REVERT_REQUIRE
### Rule Description
<p>Using the construction <code>if (condition) {revert();}</code> instead of <code>require(condition);</code></p>

### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-c56b12-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
ifStatement[statement[not(descendant::ifStatement)]//throwRevertStatement]
```

### Sample Code

```
contract f{
    function a(){
    // <yes> <report> SOLIDITY_REVERT_REQUIRE c56b12
        if (x>y) { revert(); }
    }
    modifier atStage(Stages _stage) {
    // <yes> <report> SOLIDITY_REVERT_REQUIRE c56b12
        if (stage != _stage)
            revert();
        _;
    }
}
contract f{
    function a(){
    // <yes> <report> SOLIDITY_REVERT_REQUIRE c56b12
        if (x>y) { throw; }
        if (tokensToSend > 0) {
            allocatedTokens -= tokensToSend;
    // <yes> <report> SOLIDITY_REVERT_REQUIRE c56b12
            if (!token.issue(msg.sender, tokensToSend)) {
                revert();
            }
        }
        if (ethToSend > 0) {
            allocatedEth -= ethToSend;
    // <yes> <report> SOLIDITY_REVERT_REQUIRE c56b12
            if (!msg.sender.send(ethToSend)) {
                revert();
            }
        }
        if (stage == Stages.PresaleStarted) {
            buyPresale(receiver);
        }
    // <yes> <report> SOLIDITY_REVERT_REQUIRE c56b12
        else if (stage == Stages.MainSaleStarted) {
            buyMainSale(receiver);
        } else {
            revert();
        }
    // <yes> <report> SOLIDITY_REVERT_REQUIRE c56b12
        if(!ico_ended) {
           eth_received = Add(eth_received, msg.value);
        } else {
           revert();
        }
    }
}
```

### Code Result

```
SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 49bd2a
severity: 1
line: 16
column: 19
content: throw

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 4
column: 8
content: if(x>y){revert();}

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 8
column: 8
content: if(stage!=_stage)revert();

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 16
column: 8
content: if(x>y){throw;}

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 20
column: 12
content: if(!token.issue(msg.sender,tokensToSend)){revert();}

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 27
column: 12
content: if(!msg.sender.send(ethToSend)){revert();}

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 35
column: 13
content: if(stage==Stages.MainSaleStarted){buyMainSale(receiver);}else{revert();}

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 41
column: 8
content: if(!ico_ended){eth_received=Add(eth_received,msg.value);}else{revert();}

ruleId: SOLIDITY_SEND
patternId: 430636
severity: 1
line: 27
column: 28
content: send(ethToSend)

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 2
column: 4
content: functiona(){if(x>y){revert();}}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 14
column: 4
content: functiona(){if(x>y){throw;}if(tokensToSend>0){allocatedTokens-=tokensToSend;if(!token.issue(msg.sender,tokensToSend)){revert();}}if(ethToSend>0){allocatedEth-=ethToSend;if(!msg.sender.send(ethToSend)){revert();}}if(stage==Stages.PresaleStarted){buyPresale(receiver);}elseif(stage==Stages.MainSaleStarted){buyMainSale(receiver);}else{revert();}if(!ico_ended){eth_received=Add(eth_received,msg.value);}else{revert();}}

SOLIDITY_VISIBILITY :2
SOLIDITY_DEPRECATED_CONSTRUCTIONS :1
SOLIDITY_REVERT_REQUIRE :7
SOLIDITY_SEND :1

```
