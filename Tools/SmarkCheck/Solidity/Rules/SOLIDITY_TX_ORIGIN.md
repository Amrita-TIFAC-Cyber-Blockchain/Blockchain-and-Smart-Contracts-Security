# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_TX_ORIGIN
### Rule Description
<p>
    <code>tx.origin</code> is used for authorization.
</p>
<p>
    Vulnerability type by SmartDec classification: <a href="https://github.com/smartdec/classification#authorization">
    Authorization with tx.origin</a>.
</p>

### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-12e802-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
environmentalVariable
                        [matches(text()[1], "^tx\.origin$")]
                        /parent::*
                            [parent::*
                                [not(comparison
                                    and expression/environmentalVariable[matches(text()[1], "^msg\.sender$")])
                                ]
                            ]
```



### Sample Code

```
pragma solidity 0.6.0;

contract SolidityTxOrigin {
    function dangerousWithdraw() public returns (bool) {
        address owner;
        // <yes> <report> SOLIDITY_TX_ORIGIN 12e802
        if (tx.origin == owner) {
            return true;
        }
        string memory origin = "foo";
        if (msg.sender != tx.origin) {
            revert();
        }
        require(tx.origin == msg.sender);
        // <yes> <report> SOLIDITY_TX_ORIGIN 12e802
        owner = tx.origin;
    }
}

contract Check060 {
    function foo(address a) external returns (bool, bool) {
        try SolidityTxOrigin(a).dangerousWithdraw() returns (bool v) {
            return (v, true);
        } catch Error(string memory reason) {
            return (false, false);
        } catch (bytes memory lowLevelData) {
            return (false, false);
        }
    }
}
```

### Code Result

```
SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 11
column: 8
content: if(msg.sender!=tx.origin){revert();}

ruleId: SOLIDITY_SHOULD_RETURN_STRUCT
patternId: 83hf3l
severity: 1
line: 21
column: 45
content: (bool,bool)

ruleId: SOLIDITY_TX_ORIGIN
patternId: 12e802
severity: 2
line: 7
column: 12
content: tx.origin

ruleId: SOLIDITY_TX_ORIGIN
patternId: 12e802
severity: 2
line: 16
column: 16
content: tx.origin

SOLIDITY_REVERT_REQUIRE :1
SOLIDITY_SHOULD_RETURN_STRUCT :1
SOLIDITY_TX_ORIGIN :2

```
