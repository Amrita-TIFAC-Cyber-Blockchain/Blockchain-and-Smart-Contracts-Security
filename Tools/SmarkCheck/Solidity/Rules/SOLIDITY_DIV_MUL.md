# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_DIV_MUL

![](https://img.shields.io/badge/Pattern_ID-09hhh1-gold) ![](https://img.shields.io/badge/Severity-2-brown) 

```
expression
                        [
                            muldivOperator/mulOperator
                            or functionCall/functionName/identifier[text()[1] = "mul"]
                        ]
                        [
                            descendant::divOperator
                            or descendant::functionCall/functionName/identifier[text()[1] = "div"]
                        ]
```

### Sample Code

```
pragma solidity 0.4.24;

library SafeMath {
  function mul(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }
 
  function div(uint256 a, uint256 b) internal constant returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }
}

contract DivMul {

using SafeMath for uint256;

    function test() {
        uint a1 = 1;
        uint a2 = 2;
        uint a3 =3;
        // <yes> <report> SOLIDITY_DIV_MUL 09hhh1
        uint a = a1/a2*a3;
        for (uint i = 0; a1/(a2*a3) >=i; i++) {
        }
        // <yes> <report> SOLIDITY_DIV_MUL 09hhh1
        if(a1*(a2/a3) >= 1) {
        }
        a = a1*a2/a3;

        // <yes> <report> SOLIDITY_DIV_MUL 09hhh1
        a = (a1.div(a2)).mul(a3);
        for (uint j = 0; a1/(a2.mul(a3)) >=j; j++) {
        }
        // <yes> <report> SOLIDITY_DIV_MUL 09hhh1
        if(a1.mul(a2/a3) >= 1) {
        }
        a = a1.mul(a2).div(a3);

    }
}
```
