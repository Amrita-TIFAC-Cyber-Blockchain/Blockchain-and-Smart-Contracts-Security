# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_EXACT_TIME
### Rule Description
<p>
    Strict comparison with <code>block.timestamp</code> or <code>now</code>. Miners can affect <code>block.timestamp</code> for their benefits. Thus, one should not rely on the exact value of <code>block.timestamp</code>.
</p>
<p>
    Vulnerability type by SmartDec classification: <a href="https://github.com/smartdec/classification#block-content-manipulation">
    Timestamp manipulation</a>.
</p>

### Solidity-Rules

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
### Code Result

```
SOLIDITY_EXACT_TIME
patternId: 1955d9
severity: 2
line: 8
column: 13
content: startTime+1days==block.timestamp

ruleId: SOLIDITY_EXACT_TIME
patternId: 1955d9
severity: 2
line: 10
column: 13
content: startTime+1days!=now

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 5
column: 4
content: functiondoSomething(){uintstartTime=now;if(startTime+1days==block.timestamp){}if(startTime+1days!=now){}require(true==ICOisEnd(now));require(now>=startTime&&now<=startTime+1days);require(now>startTime+1days);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 16
column: 4
content: functionICOisEnd(uint_time)returns(bool){return_time>1000000000;}

SOLIDITY_VISIBILITY :2
SOLIDITY_EXACT_TIME :2


```

