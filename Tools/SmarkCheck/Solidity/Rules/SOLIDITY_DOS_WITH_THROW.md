# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_DOS_WITH_THROW

![](https://img.shields.io/badge/Pattern_ID-637fdc-gold) ![](https://img.shields.io/badge/Severity-3-brown) 

```
//ifStatement[condition//externalFunctionCall][block/statement//throwRevertStatement]
```

![](https://img.shields.io/badge/Pattern_ID-efb788-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
//forStatement/expression//externalFunctionCall
```

![](https://img.shields.io/badge/Pattern_ID-04242c-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
//whileStatement/whileCondition//externalFunctionCall
```

### Sample Code

```
pragma solidity ^0.4.5;
contract Auction {
    /* address addr;
    function bid() payable {
        // <_yes> <report> SOLIDITY_DOS_WITH_THROW 637fdc
        if (currentLeader.send(highestBid)) { throw; }
        // <_yes> <report> SOLIDITY_DOS_WITH_THROW 637fdc
        if (!currentLeader.send(highestBid)) { revert; } 

        // <_yes> <report> SOLIDITY_DOS_WITH_THROW efb788
        for(uint x; x < refundAddresses[x].transfer(1 wei); x++) {
            addr.transfer(1 wei);
        }

        // <_yes> <report> SOLIDITY_DOS_WITH_THROW 04242c
        while ( x > refundAddresses[x].transfer(1 wei)) {
            refundAddresses[x].transfer(1 wei);
        }
    } */
}
```