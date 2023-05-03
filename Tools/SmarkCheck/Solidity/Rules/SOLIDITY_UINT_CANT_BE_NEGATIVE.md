# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_UINT_CANT_BE_NEGATIVE
### Rule Description
<p>
    Variables of <code>uint</code> type cannot be negative. Thus, comparing <code>uint</code> variable with zero (greater than or equal) is redundant. Also, it may lead to an underflow issue. Moreover, comparison with zero used in <code>for</code>-loop condition results in an infinite loop.
</p>

### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-11ca45b-gold) ![](https://img.shields.io/badge/Severity-3-brown) 

```
(forStatement | whileStatement | doWhileStatement)
                        /condition/expression
                            [text()[1] = ">="]
                            [expression[2]/primaryExpression//decimalNumber[text()[1] = "0"]]
                            [expression[1]/primaryExpression/identifier
                                [text()[1]
                                    = ancestor::functionDefinition//variableDeclaration
                                        [typeName/elementaryTypeName[matches(text()[1], "uint")]]
                                        /identifier/text()[1]
                                ]
                            ]
```

![](https://img.shields.io/badge/Pattern_ID-d48ac4-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
expression
                        [text()[1] = ">="]
                        [expression[2]/primaryExpression//decimalNumber[text()[1] = "0"]]
                        [expression[1]/(primaryExpression/identifier | identifier)
                            [
                                text()[1]
                                    = ancestor::functionDefinition//variableDeclaration
                                        [typeName/elementaryTypeName[matches(text()[1], "uint")]]
                                        /identifier/text()[1]
                                or text()[1]
                                    = ancestor::contractDefinition//(structDefinition/variableDeclaration | stateVariableDeclaration)
                                        [typeName/elementaryTypeName[matches(text()[1], "uint")]]
                                        /identifier/text()[1]
                            ]
                        ]
```

![](https://img.shields.io/badge/Pattern_ID-733fdd-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
expression
                        [text()[1]=">="]
                        [expression[2]//decimalNumber[text()[1] = "0"]]
                        [expression[1]/expression[1]//identifier
                            [text()[1]
                                = ancestor::contractDefinition//stateVariableDeclaration
                                    [typeName/mappingSt/typeName[2]/elementaryTypeName[matches(text()[1],"uint")]]
                                    /identifier/text()[1]
                            ]
                        ]
```

### Sample Code

```
pragma solidity 0.4.24;

contract UnderFlow {
    uint8 a;

    function foo_1() {
        uint b;
        int c = 1;
    // <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  11ca45b <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  d48ac4
        for (uint i=100; i >= 0; i--) {
        }
        for (uint j=0; j <= 0; j--) {
        }
        for (uint k=100; k >= 1; k--) {
        }
    // <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  d48ac4
        require(a >= 0);
        require(a <= 0);
    // <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  d48ac4
        require(b >= 0);
        require(b >= 7);
        require(c >= 0);
    }

    struct Mystruct {
        uint a1;
        int a2;
    }

    function foo_2(Mystruct str) internal {
    // <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  d48ac4
        require(str.a1 >= 0);
        require(str.a2 >= 0);
    }

    mapping(address => uint) balances;
    mapping(address => int) ibalances;

    function foo_3(address user) {
    // <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  733fdd
        require(balances[user] >= 0);
        require(ibalances[user] >= 0);
    }

    function foo_4() {
        uint i;
    // <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  11ca45b <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  d48ac4
        while(i >= 0) {
            i--;
        }
        do {
            i--;
    // <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  11ca45b <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  d48ac4
        } while(i >=0);

        for (uint i=100; i <= 0; i++) {
    // <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  11ca45b <yes> <report> SOLIDITY_UINT_CANT_BE_NEGATIVE  d48ac4
            for (uint i=100; i >= 0; i--) {
            }
        }
    }
}
```
### Code Result

```
SOLIDITY_UINT_CANT_BE_NEGATIVE
patternId: 11ca45b
severity: 3
line: 10
column: 25
content: i>=0

ruleId: SOLIDITY_UINT_CANT_BE_NEGATIVE
patternId: 11ca45b
severity: 3
line: 48
column: 14
content: i>=0

ruleId: SOLIDITY_UINT_CANT_BE_NEGATIVE
patternId: 11ca45b
severity: 3
line: 54
column: 16
content: i>=0

ruleId: SOLIDITY_UINT_CANT_BE_NEGATIVE
patternId: 11ca45b
severity: 3
line: 58
column: 29
content: i>=0

ruleId: SOLIDITY_UINT_CANT_BE_NEGATIVE
patternId: d48ac4
severity: 2
line: 10
column: 25
content: i>=0

ruleId: SOLIDITY_UINT_CANT_BE_NEGATIVE
patternId: d48ac4
severity: 2
line: 17
column: 16
content: a>=0

ruleId: SOLIDITY_UINT_CANT_BE_NEGATIVE
patternId: d48ac4
severity: 2
line: 20
column: 16
content: b>=0

ruleId: SOLIDITY_UINT_CANT_BE_NEGATIVE
patternId: d48ac4
severity: 2
line: 32
column: 16
content: str.a1>=0

ruleId: SOLIDITY_UINT_CANT_BE_NEGATIVE
patternId: d48ac4
severity: 2
line: 48
column: 14
content: i>=0

ruleId: SOLIDITY_UINT_CANT_BE_NEGATIVE
patternId: d48ac4
severity: 2
line: 54
column: 16
content: i>=0

ruleId: SOLIDITY_UINT_CANT_BE_NEGATIVE
patternId: d48ac4
severity: 2
line: 58
column: 29
content: i>=0

ruleId: SOLIDITY_UINT_CANT_BE_NEGATIVE
patternId: 733fdd
severity: 2
line: 41
column: 16
content: balances[user]>=0

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 341gim
severity: 1
line: 30
column: 19
content: Mystructstr

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 6
column: 4
content: functionfoo_1(){uintb;intc=1;for(uinti=100;i>=0;i--){}for(uintj=0;j<=0;j--){}for(uintk=100;k>=1;k--){}require(a>=0);require(a<=0);require(b>=0);require(b>=7);require(c>=0);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 39
column: 4
content: functionfoo_3(addressuser){require(balances[user]>=0);require(ibalances[user]>=0);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 45
column: 4
content: functionfoo_4(){uinti;while(i>=0){i--;}do{i--;}while(i>=0);for(uinti=100;i<=0;i++){for(uinti=100;i>=0;i--){}}}

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 4
column: 4
content: uint8a;

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 36
column: 4
content: mapping(address=>uint)balances;

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 37
column: 4
content: mapping(address=>int)ibalances;

SOLIDITY_VISIBILITY :6
SOLIDITY_UPGRADE_TO_050 :1
SOLIDITY_UINT_CANT_BE_NEGATIVE :12


```

