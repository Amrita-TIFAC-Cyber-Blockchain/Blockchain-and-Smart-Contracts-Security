# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_ADDRESS_HARDCODED

### Rule Description
The contract contains unknown address. This address might be used for some malicious activity. Please check hardcoded address and it's usage.
### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-adc165-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
hexNumber[string-length() = 42]
```

![](https://img.shields.io/badge/Pattern_ID-b140cd-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
hexNumber
[
    (string-length() lt 42)
    and (string-length() gt 30)
    and not(matches(text()[1], "^0x0$"))
]
```

![](https://img.shields.io/badge/Pattern_ID-f32db1-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
typeConversion
	[typeName[elementaryTypeName[matches(text()[1], "^address$")]]]
	/expression
		[primaryExpression/numberLiteral/decimalNumber]
		[
			not(primaryExpression/numberLiteral/decimalNumber[matches(text()[1], "^0$")])
			and not(primaryExpression/identifier[matches(text()[1], "^this$")])
		]
```

### Sample Code

```
pragma solidity 0.4.24;

contract C {
    
    event Transfer(address s, uint amount);
    
    function g(address s) returns(address) {
        return s;
    }
    
    function badPractice() {
        // <yes> <report> SOLIDITY_ADDRESS_HARDCODED  adc165
        address x = 0xf64B584972FE6055a770477670208d737Fff282f;
        // <yes> <report> SOLIDITY_ADDRESS_HARDCODED  adc165
        x = g(0x72ba7d8e73fe8eb666ea66babc8116a41bfb10e2);
        // too short - not an address
        x = 0x123;
        // <yes> <report> SOLIDITY_ADDRESS_HARDCODED  f32db1
        x = address(342);
        x = address(0);        
        x = g(address(0));
        x = 0x0;
        x = g(0x0);
    }
    
    function goodPractice(address _token, uint balance) {

        if ((address(0) == _token)||(0x0 == _token)) {
            Transfer(address(0), balance);
        }
        if ((address(0) != _token)||(0x0 != _token)) {
            Transfer(0x0, balance);
        }      
    }
}
```
### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/40423f44cbd7a49cb72f7d4d607f07fd/490408b3f6b61b27161a0a7b17479a879c930f22) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_

### Code Result

```
SOLIDITY_ADDRESS_HARDCODED
patternId: adc165
severity: 1
line: 13
column: 20
content: 0xf64B584972FE6055a770477670208d737Fff282f

ruleId: SOLIDITY_ADDRESS_HARDCODED
patternId: adc165
severity: 1
line: 15
column: 14
content: 0x72ba7d8e73fe8eb666ea66babc8116a41bfb10e2

ruleId: SOLIDITY_ADDRESS_HARDCODED
patternId: b140cd
severity: 1
line: 17
column: 12
content: 0x123

ruleId: SOLIDITY_ADDRESS_HARDCODED
patternId: f32db1
severity: 1
line: 19
column: 20
content: 342

ruleId: SOLIDITY_ADDRESS_HARDCODED
patternId: a91b18
severity: 1
line: 20
column: 8
content: x=address(0)

ruleId: SOLIDITY_ADDRESS_HARDCODED
patternId: a91b18
severity: 1
line: 21
column: 13
content: (address(0))

ruleId: SOLIDITY_ADDRESS_HARDCODED
patternId: c67a09
severity: 1
line: 22
column: 12
content: 0x0

ruleId: SOLIDITY_ADDRESS_HARDCODED
patternId: c67a09
severity: 1
line: 23
column: 14
content: 0x0

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 7
column: 4
content: functiong(addresss)returns(address){returns;}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 11
column: 4
content: functionbadPractice(){addressx=0xf64B584972FE6055a770477670208d737Fff282f;x=g(0x72ba7d8e73fe8eb666ea66babc8116a41bfb10e2);x=0x123;x=address(342);x=address(0);x=g(address(0));x=0x0;x=g(0x0);}

ruleId: SOLIDITY_VISIBILITY
patternId: 910067
severity: 1
line: 26
column: 4
content: functiongoodPractice(address_token,uintbalance){if((address(0)==_token)||(0x0==_token)){Transfer(address(0),balance);}if((address(0)!=_token)||(0x0!=_token)){Transfer(0x0,balance);}}

SOLIDITY_VISIBILITY :3
SOLIDITY_ADDRESS_HARDCODED :8
```
