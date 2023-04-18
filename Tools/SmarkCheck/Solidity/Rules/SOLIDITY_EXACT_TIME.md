# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_EXACT_TIME

![](https://img.shields.io/badge/Pattern_ID-1955d9-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
expression
                        [comparison]
                        [expression//environmentalVariable
                            [matches(text()[1], "^block\.timestamp|now$")]
                            [not(ancestor::*[4][self::functionCall])]]
```


### Sample Code

```
pragma solidity 0.4.24;

contract TimestampDependence {

    function doSomething() {
        uint startTime = now;
        // <yes> <report> SOLIDITY_EXACT_TIME 1955d9
        if ( startTime + 1 days == block.timestamp) {}
        // <yes> <report> SOLIDITY_EXACT_TIME 1955d9
        if ( startTime + 1 days != now) {}
        require(true == ICOisEnd(now));
        require(now >= startTime && now <= startTime + 1 days);
        require(now > startTime + 1 days);
    }

    function ICOisEnd(uint _time) returns(bool) {
        return _time > 1000000000;
    }
}
```
