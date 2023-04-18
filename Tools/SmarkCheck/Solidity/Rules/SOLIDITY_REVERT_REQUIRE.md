# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_REVERT_REQUIRE

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