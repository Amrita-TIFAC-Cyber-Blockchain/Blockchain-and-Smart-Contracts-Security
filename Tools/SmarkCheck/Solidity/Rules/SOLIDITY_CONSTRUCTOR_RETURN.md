# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_CONSTRUCTOR_RETURN
### Rule Description
Statement is used in contract's constructor. With code return the process of deploy will differ from the intuitive one. For instance, deployed bytecode may not include functions implemented in the source.
### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-8saf21-gold) ![](https://img.shields.io/badge/Severity-3-brown) 

```
functionDefinition
                        [text()[1] = "constructor"]
                        //assemblyCall[matches(text()[1], "^return\(")]
```

![](https://img.shields.io/badge/Pattern_ID-7gaf21-gold) ![](https://img.shields.io/badge/Severity-3-brown) 

```
functionDefinition
                        [identifier[text()[1] = (ancestor::contractDefinition/identifier)]]
                        //assemblyCall[matches(text()[1], "^return\(")]
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

contract HoneyPot {

    bytes internal constant ID = hex"60203414600857005B60008080803031335AF100";

    constructor () public payable {
        bytes memory contract_identifier = ID;
        // <yes> <report> SOLIDITY_CONSTRUCTOR_RETURN 8saf21
        assembly { return(add(0x20, contract_identifier), mload(contract_identifier)) }
    }

    function withdraw() public payable {
        require(msg.value >= 1 ether);
        msg.sender.transfer(address(this).balance);
    }
}

contract HoneyPotOldSchool {

    bytes internal constant ID = hex"60203414600857005B60008080803031335AF100";

    function HoneyPotOldSchool() public payable {
        bytes memory contract_identifier = ID;
        // <yes> <report> SOLIDITY_CONSTRUCTOR_RETURN 7gaf21
        assembly { return(add(0x20, contract_identifier), mload(contract_identifier)) }
    }

    function withdraw() public payable {
        require(msg.value >= 1 ether);
        msg.sender.transfer(address(this).balance);
    }
}

contract FPTest {

    function FPTest(address target) public payable {
        assembly {
            let freeMemoryPtrPosition := 0x40
            let calldataMemoryOffset := mload(freeMemoryPtrPosition)
            mstore(freeMemoryPtrPosition, add(calldataMemoryOffset, calldatasize))
            calldatacopy(calldataMemoryOffset, 0x0, calldatasize)

            let ret := delegatecall(gas, target, calldataMemoryOffset, calldatasize, 0, 0)

            let returndataMemoryOffset := mload(freeMemoryPtrPosition)
            mstore(freeMemoryPtrPosition, add(returndataMemoryOffset, returndatasize))
            returndatacopy(returndataMemoryOffset, 0x0, returndatasize)

            switch ret
            case 0 {
                revert(returndataMemoryOffset, returndatasize)
            }
        }
    }
}
```

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/96230932ac5e35876877f42c0d89ba34/4a1f05bbaa58c56b46970ca9b4a227b9dc18046e) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_


### Code Result

```
SOLIDITY_CONSTRUCTOR_RETURN
patternId: 8saf21
severity: 3
line: 10
column: 19
content: return(add(0x20,contract_identifier),mload(contract_identifier))

ruleId: SOLIDITY_CONSTRUCTOR_RETURN
patternId: 7gaf21
severity: 3
line: 26
column: 19
content: return(add(0x20,contract_identifier),mload(contract_identifier))

ruleId: SOLIDITY_LOCKED_MONEY
patternId: 30281d
severity: 3
line: 35
column: 0
content: contractFPTest{functionFPTest(addresstarget)publicpayable{assembly{letfreeMemoryPtrPosition:=0x40letcalldataMemoryOffset:=mload(freeMemoryPtrPosition)mstore(freeMemoryPtrPosition,add(calldataMemoryOffset,calldatasize))calldatacopy(calldataMemoryOffset,0x0,calldatasize)letret:=delegatecall(gas,target,calldataMemoryOffset,calldatasize,0,0)letreturndataMemoryOffset:=mload(freeMemoryPtrPosition)mstore(freeMemoryPtrPosition,add(returndataMemoryOffset,returndatasize))returndatacopy(returndataMemoryOffset,0x0,returndatasize)switchretcase0{revert(returndataMemoryOffset,returndatasize)}}}}

ruleId: SOLIDITY_USING_INLINE_ASSEMBLY
patternId: 109cd5
severity: 1
line: 10
column: 8
content: assembly{return(add(0x20,contract_identifier),mload(contract_identifier))}

ruleId: SOLIDITY_USING_INLINE_ASSEMBLY
patternId: 109cd5
severity: 1
line: 26
column: 8
content: assembly{return(add(0x20,contract_identifier),mload(contract_identifier))}

ruleId: SOLIDITY_USING_INLINE_ASSEMBLY
patternId: 109cd5
severity: 1
line: 38
column: 8
content: assembly{letfreeMemoryPtrPosition:=0x40letcalldataMemoryOffset:=mload(freeMemoryPtrPosition)mstore(freeMemoryPtrPosition,add(calldataMemoryOffset,calldatasize))calldatacopy(calldataMemoryOffset,0x0,calldatasize)letret:=delegatecall(gas,target,calldataMemoryOffset,calldatasize,0,0)letreturndataMemoryOffset:=mload(freeMemoryPtrPosition)mstore(freeMemoryPtrPosition,add(returndataMemoryOffset,returndatasize))returndatacopy(returndataMemoryOffset,0x0,returndatasize)switchretcase0{revert(returndataMemoryOffset,returndatasize)}}

SOLIDITY_LOCKED_MONEY :1
SOLIDITY_USING_INLINE_ASSEMBLY :3
SOLIDITY_CONSTRUCTOR_RETURN :2


```

