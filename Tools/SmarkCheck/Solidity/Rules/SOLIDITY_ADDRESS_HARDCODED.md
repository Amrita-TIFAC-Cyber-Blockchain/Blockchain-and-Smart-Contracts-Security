# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
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