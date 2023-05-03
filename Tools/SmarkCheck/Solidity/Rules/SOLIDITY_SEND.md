# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_SEND
### Rule Description
<p>
    The <code>send</code> function is called inside checks instead of using <code>transfer</code>.
</p>
<p>
    The recommended way to perform checked ether payments is <code>addr.transfer(x)</code>, which automatically throws an exception if the transfer is unsuccessful.
</p>

### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-430636-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
expression
                        [text()[1] = "."]
                        [not(expression[1]/typeConversion/typeName/elementaryTypeName[matches(text()[1], "^address$|^address payable$")])]
                        /functionCall
                            [functionName/identifier[text()[1] = "send"]]
                            [callArguments/tupleExpression[count(expression) = 1]]
                            [
                                ancestor::condition
                                    [expression/text()[1] = "!"]
                                    /parent::ifStatement/statement/block/statement/throwRevertStatement
                                or ancestor::functionCall
                                    [not(callArguments/tupleExpression/expression/text()[1] = "!")]
                                    /functionName/identifier
                                        [matches(text()[1], "^require$|^assert$")]
                            ]
```

![](https://img.shields.io/badge/Pattern_ID-we5gu5-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
expression
                        [text()[1] = "."]
                        [expression[1]/typeConversion/typeName/elementaryTypeName[matches(text()[1], "^address$|^address payable$")]]
                        /functionCall
                            [functionName/identifier[text()[1] = "send"]]
                            [callArguments/tupleExpression[count(expression) = 1]]
                            [
                                ancestor::condition
                                    [expression/text()[1] = "!"]
                                    /parent::ifStatement/statement/block/statement/throwRevertStatement
                                or ancestor::functionCall
                                    [not(callArguments/tupleExpression/expression/text()[1] = "!")]
                                    /functionName/identifier
                                        [matches(text()[1], "^require$|^assert$")]
                            ]
```

### Sample Code

```
pragma solidity 0.4.24;

contract SoliditySend {

    function payOut() {
        uint i=50;
        while ( i < 100 && msg.gas > 200000) {
            msg.sender.send(msg.value);
            i++;
        }
        if (true) {
            msg.sender.send(1);
            revert();
        }
        if (msg.sender.send(1)) { revert();}
        if (address(msg.sender).send(1)) { throw;}
        require(!address payable(msg.sender).send(1));
        assert(!address payable(uint160(msg.sender)).send(1));

// <yes> <report> SOLIDITY_SEND 430636
        if (!msg.sender.send(1)) { revert();}
// <yes> <report> SOLIDITY_SEND 430636
        if (!msg.sender.send(1)) { throw;}
// <yes> <report> SOLIDITY_SEND 430636
        require(msg.sender.send(1));
// <yes> <report> SOLIDITY_SEND 430636
        assert(msg.sender.send(1));
        // <yes> <report> SOLIDITY_SEND we5gu5
        if (!address(msg.sender).send(1)) { revert();}
        // <yes> <report> SOLIDITY_SEND we5gu5
        if (!address(msg.sender).send(1)) { throw;}
        // <yes> <report> SOLIDITY_SEND we5gu5
        require(address(msg.sender).send(1));
        // <yes> <report> SOLIDITY_SEND we5gu5
        assert(address(msg.sender).send(1));
        // <yes> <report> SOLIDITY_SEND we5gu5
        if (!address payable(msg.sender).send(1)) { revert();}
        // <yes> <report> SOLIDITY_SEND we5gu5
        if (!address payable(msg.sender).send(1)) { throw;}
        // <yes> <report> SOLIDITY_SEND we5gu5
        require(address payable(msg.sender).send(1));
        // <yes> <report> SOLIDITY_SEND we5gu5
        assert(address payable(uint160(msg.sender)).send(1));
    }
}
```

### Code Result

```
SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 49bd2a
severity: 1
line: 16
column: 43
content: throw

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 49bd2a
severity: 1
line: 23
column: 35
content: throw

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 49bd2a
severity: 1
line: 31
column: 44
content: throw

ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 49bd2a
severity: 1
line: 39
column: 52
content: throw

ruleId: SOLIDITY_GAS_LIMIT_IN_LOOPS
patternId: 17f23a
severity: 1
line: 7
column: 16
content: i<100&&msg.gas>200000

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 11
column: 8
content: if(true){msg.sender.send(1);revert();}

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 15
column: 8
content: if(msg.sender.send(1)){revert();}

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 16
column: 8
content: if(address(msg.sender).send(1)){throw;}

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 21
column: 8
content: if(!msg.sender.send(1)){revert();}

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 23
column: 8
content: if(!msg.sender.send(1)){throw;}

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 29
column: 8
content: if(!address(msg.sender).send(1)){revert();}

ruleId: SOLIDITY_REVERT_REQUIRE
patternId: c56b12
severity: 1
line: 31
column: 8
content: if(!address(msg.sender).send(1)){throw;}

ruleId: SOLIDITY_SEND
patternId: 430636
severity: 1
line: 12
column: 23
content: send(1)

ruleId: SOLIDITY_SEND
patternId: 430636
severity: 1
line: 15
column: 23
content: send(1)

ruleId: SOLIDITY_SEND
patternId: 430636
severity: 1
line: 16
column: 32
content: send(1)

ruleId: SOLIDITY_SEND
patternId: 430636
severity: 1
line: 21
column: 24
content: send(1)

ruleId: SOLIDITY_SEND
patternId: 430636
severity: 1
line: 23
column: 24
content: send(1)

ruleId: SOLIDITY_SEND
patternId: 430636
severity: 1
line: 25
column: 27
content: send(1)

ruleId: SOLIDITY_SEND
patternId: 430636
severity: 1
line: 27
column: 26
content: send(1)

ruleId: SOLIDITY_SEND
patternId: 430636
severity: 1
line: 29
column: 33
content: send(1)

ruleId: SOLIDITY_SEND
patternId: 430636
severity: 1
line: 31
column: 33
content: send(1)

ruleId: SOLIDITY_SEND
patternId: 430636
severity: 1
line: 33
column: 36
content: send(1)

ruleId: SOLIDITY_SEND
patternId: 430636
severity: 1
line: 35
column: 35
content: send(1)

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 8
column: 23
content: send(msg.value)

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 17
column: 45
content: send(1)

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 18
column: 53
content: send(1)

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 37
column: 41
content: send(1)

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 39
column: 41
content: send(1)

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 41
column: 44
content: send(1)

ruleId: SOLIDITY_UNCHECKED_CALL
patternId: f39eed
severity: 3
line: 43
column: 52
content: send(1)

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 5
column: 4
content: functionpayOut(){uinti=50;while(i<100&&msg.gas>200000){msg.sender.send(msg.value);i++;}if(true){msg.sender.send(1);revert();}if(msg.sender.send(1)){revert();}if(address(msg.sender).send(1)){throw;}require(!<missing ';'><missing ';'>addresspayable<missing ';'>(msg.sender).send(1));assert(!<missing ';'><missing ';'>addresspayable<missing ';'>(uint160(msg.sender)).send(1));if(!msg.sender.send(1)){revert();}if(!msg.sender.send(1)){throw;}require(msg.sender.send(1));assert(msg.sender.send(1));if(!address(msg.sender).send(1)){revert();}if(!address(msg.sender).send(1)){throw;}require(address(msg.sender).send(1));assert(address(msg.sender).send(1));if(!<missing ')'><missing ';'>addresspayable<missing ';'>(msg.sender).send(1)){revert();}if(!<missing ')'><missing ';'>addresspayable<missing ';'>(msg.sender).send(1)){throw;}require(<missing ';'><missing ';'>addresspayable<missing ';'>(msg.sender).send(1));assert(<missing ';'><missing ';'>addresspayable<missing ';'>(uint160(msg.sender)).send(1));}

SOLIDITY_VISIBILITY :1
SOLIDITY_DEPRECATED_CONSTRUCTIONS :4
SOLIDITY_REVERT_REQUIRE :7
SOLIDITY_SEND :11
SOLIDITY_GAS_LIMIT_IN_LOOPS :1
SOLIDITY_UNCHECKED_CALL :7


```
