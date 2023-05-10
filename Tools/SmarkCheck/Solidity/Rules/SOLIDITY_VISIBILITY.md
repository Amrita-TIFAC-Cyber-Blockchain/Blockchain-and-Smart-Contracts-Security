# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_VISIBILITY
### Rule Description
<p>
    The default function visibility level in contracts is <code>public</code>, in interfaces - <code>external</code>, state variable default visibility level is <code>internal</code>.
    In contracts, the fallback function can be <code>external</code> or <code>public</code>. In interfaces, all the functions should be declared as <code>external</code>. Explicitly define function visibility to prevent confusion.
</p>

### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-23rt6g-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
interfaceDefinition/contractPartDefinition
                        /(functionDefinition | functionFallBackDefinition)
                        /visibleType[not(matches(text()[1], "^external$"))]
```

![](https://img.shields.io/badge/Pattern_ID-910067-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
(functionDefinition | functionFallBackDefinition)[not(visibleType)]
```

![](https://img.shields.io/badge/Pattern_ID-d67c21-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
contractDefinition/contractPartDefinition/functionFallBackDefinition/visibleType
                        [not(matches(text()[1], "^external$|^public$"))]
```


![](https://img.shields.io/badge/Pattern_ID-b51ce0-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
stateVariableDeclaration[not(visibleType)]
```


![](https://img.shields.io/badge/Pattern_ID-321aca-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
functionDefinition
                        [text()[1] = "constructor"]
                        [visibleType[matches(text()[1], "^external$|^private$")]]
```

### Sample Code

```
pragma solidity 0.4.23;

contract SolidityVisibility1 {

// <yes> <report> SOLIDITY_VISIBILITY b51ce0
    uint x;
    uint private y;

// <yes> <report> SOLIDITY_VISIBILITY 910067
    function transfer() {
        x=0;
    }

    function isServer(address sender) public constant returns (bool) {
        return sender == msg.sender;
    }

    function transfernew() external {
    }

    function transfernew2() private {
    }

    function internalAction() internal {
    }

// <yes> <report> SOLIDITY_VISIBILITY d67c21
    function () private {
    }
}


contract SolidityVisibility2 {

// <yes> <report> SOLIDITY_VISIBILITY 910067
    constructor () {
        address owner = msg.sender;
    }
// <yes> <report> SOLIDITY_VISIBILITY 321aca
    constructor () external {
        address owner = msg.sender;
    }
// <yes> <report> SOLIDITY_VISIBILITY 321aca
    constructor () private {
        address owner = msg.sender;
    }
// <yes> <report> SOLIDITY_VISIBILITY 910067
    function AccessManager(address _server, address _guardian) returns(address){
        return _server;
    }

// <yes> <report> SOLIDITY_VISIBILITY 910067
    function () {
    }
}


interface SolidityVisibility3 {

// <yes> <report> SOLIDITY_VISIBILITY 910067
    function noVisibility1 ();

// <yes> <report> SOLIDITY_VISIBILITY 23rt6g
    function noVisibility2 () public;

// <yes> <report> SOLIDITY_VISIBILITY 23rt6g
    function noVisibility3 () private;

// <yes> <report> SOLIDITY_VISIBILITY 23rt6g
    function noVisibility4 () internal;

    function noVisibility5 () external;

    function () external;

} 


contract SolidityVisibility4 {

    function () public {
    }
}


contract SolidityVisibility5 {

    function () external {
    }
}


contract SolidityVisibility6 {

// <yes> <report> SOLIDITY_VISIBILITY d67c21
    function () internal {
    }
}

interface SolidityVisibility7 {
// <yes> <report> SOLIDITY_VISIBILITY 23rt6g
    function () public;
} 


interface SolidityVisibility8 {
// <yes> <report> SOLIDITY_VISIBILITY 910067
    function ();
} 


interface SolidityVisibility9 {
// <yes> <report> SOLIDITY_VISIBILITY 23rt6g
    function () private;
} 


library LibraryVisibility {
// <yes> <report> SOLIDITY_VISIBILITY 910067
    function noVisibility () {
    }

    function withVisibility () public {
    }
}
```

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/f0054e13416a9a090423809064766997/48ad9637569e9aa3a4ddd3d4129b8745f85b2aa5) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_

### Code Result

```
ruleId: SOLIDITY_DEPRECATED_CONSTRUCTIONS
patternId: 28fa69
severity: 1
line: 14
column: 4
content: functionisServer(addresssender)publicconstantreturns(bool){returnsender==msg.sender;}

ruleId: SOLIDITY_PRIVATE_MODIFIER_DONT_HIDE_DATA
patternId: 5616b2
severity: 1
line: 7
column: 9
content: private

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 91h3sa
severity: 1
line: 28
column: 16
content: private

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 91h3sa
severity: 1
line: 81
column: 16
content: public

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 91h3sa
severity: 1
line: 96
column: 16
content: internal

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 91h3sa
severity: 1
line: 102
column: 16
content: public

ruleId: SOLIDITY_UPGRADE_TO_050
patternId: 91h3sa
severity: 1
line: 114
column: 16
content: private

ruleId: SOLIDITY_VISIBILITY
patternId: 23rt6g
severity: 1
line: 64
column: 30
content: public

ruleId: SOLIDITY_VISIBILITY
patternId: 23rt6g
severity: 1
line: 67
column: 30
content: private

ruleId: SOLIDITY_VISIBILITY
patternId: 23rt6g
severity: 1
line: 70
column: 30
content: internal

ruleId: SOLIDITY_VISIBILITY
patternId: 23rt6g
severity: 1
line: 102
column: 16
content: public

ruleId: SOLIDITY_VISIBILITY
patternId: 23rt6g
severity: 1
line: 114
column: 16
content: private

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 10
column: 4
content: functiontransfer(){x=0;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 36
column: 4
content: constructor(){addressowner=msg.sender;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 48
column: 4
content: functionAccessManager(address_server,address_guardian)returns(address){return_server;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 53
column: 4
content: function(){}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 61
column: 4
content: functionnoVisibility1();

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 108
column: 4
content: function();

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 120
column: 4
content: functionnoVisibility(){}

ruleId: SOLIDITY_VISIBILITY
patternId: d67c21
severity: 1
line: 28
column: 16
content: private

ruleId: SOLIDITY_VISIBILITY
patternId: d67c21
severity: 1
line: 96
column: 16
content: internal

ruleId: SOLIDITY_VISIBILITY
patternId: b51ce0
severity: 1
line: 6
column: 4
content: uintx;

ruleId: SOLIDITY_VISIBILITY
patternId: 321aca
severity: 1
line: 40
column: 4
content: constructor()external{addressowner=msg.sender;}

ruleId: SOLIDITY_VISIBILITY
patternId: 321aca
severity: 1
line: 44
column: 4
content: constructor()private{addressowner=msg.sender;}

SOLIDITY_VISIBILITY :17
SOLIDITY_DEPRECATED_CONSTRUCTIONS :1
SOLIDITY_PRIVATE_MODIFIER_DONT_HIDE_DATA :1
SOLIDITY_UPGRADE_TO_050 :5

```

