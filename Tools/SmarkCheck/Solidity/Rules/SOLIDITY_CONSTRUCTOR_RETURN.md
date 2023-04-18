# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-20CYS-green) ![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-20CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_CONSTRUCTOR_RETURN

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