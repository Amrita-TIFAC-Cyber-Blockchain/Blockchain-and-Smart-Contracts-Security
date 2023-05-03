# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_OVERPOWERED_ROLE
### Rule Description
<p>
    This function is callable only from one address. Therefore, the system depends heavily on this address. In this case, there are scenarios that may lead to undesirable consequences for investors, e.g. if the private key of this address becomes compromised.
</p>
<p>
    Vulnerability type by SmartDec classification: <a href="https://github.com/smartdec/classification#trust">
    Overpowered owner</a>.
</p>

### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-j83hf7-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
functionDefinition
                        [parameterList/parameter]
                        [
                            identifier[text()[1] = "onlyOwner"]
                            or identifier[text()[1] = "onlyOwner()"]
                            or descendant::expression
                                [comparison[text()[1] = "=="]]
                                [expression/environmentalVariable[text()[1] = "msg.sender"]]
                                [expression/primaryExpression/identifier
                                    [text()[1] =
                                        ancestor::contractDefinition//stateVariableDeclaration
                                            [typeName/elementaryTypeName[text()[1] = "address"]]/identifier/text()[1]
                                    ]
                                ]
                        ]
                        [identifier[matches(text()[1], "^set|^init")]]
```

### Sample Code

```
pragma solidity 0.4.24;

contract MyTreasure {
    address public myAddr;
    uint public price;

    modifier onlyOwner() {
        require(msg.sender == myAddr);
        _;
    }
    // <yes> <report> SOLIDITY_OVERPOWERED_ROLE j83hf7
    function setPrice(uint _price) public onlyOwner {
        price = _price;
    } 
    // <yes> <report> SOLIDITY_OVERPOWERED_ROLE j83hf7
    function initNewPrice(uint _price) public {
        require(msg.sender == myAddr);
        price = _price;
    }
    // <yes> <report> SOLIDITY_OVERPOWERED_ROLE j83hf7
    function setNewPrice(uint _price) public {
        require(myAddr == msg.sender);
        price = _price;
    }

    function withdrawAll(uint _price) public onlyOwner {
        myAddr.transfer(this.balance);
    }

    function setAll() public {
        require(msg.sender == myAddr);
        myAddr.transfer(this.balance);
    }

    function setMy(uint _price) public {
        myAddr.transfer(this.balance);
    }

    function setNew() public returns() {
        require(msg.sender == myAddr);
    }
}
```
### Code Result

```
SOLIDITY_OVERPOWERED_ROLE
patternId: j83hf7
severity: 2
line: 12
column: 4
content: functionsetPrice(uint_price)publiconlyOwner{price=_price;}

ruleId: SOLIDITY_OVERPOWERED_ROLE
patternId: j83hf7
severity: 2
line: 16
column: 4
content: functioninitNewPrice(uint_price)public{require(msg.sender==myAddr);price=_price;}

ruleId: SOLIDITY_OVERPOWERED_ROLE
patternId: j83hf7
severity: 2
line: 21
column: 4
content: functionsetNewPrice(uint_price)public{require(myAddr==msg.sender);price=_price;}

SOLIDITY_OVERPOWERED_ROLE :3

```

