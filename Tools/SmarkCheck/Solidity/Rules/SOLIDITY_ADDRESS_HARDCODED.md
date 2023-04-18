# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_ADDRESS_HARDCODED

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
