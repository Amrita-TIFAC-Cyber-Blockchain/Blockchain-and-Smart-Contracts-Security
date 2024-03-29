# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)
![](https://img.shields.io/badge/Batch-UG21CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-UG22CYS-lightgreen) ![](https://img.shields.io/badge/Batch-PG21CYS-green) ![](https://img.shields.io/badge/Batch-PhD-darkgreen) ![](https://img.shields.io/badge/-B_RIG-darkgreen)<br/>   ![](https://img.shields.io/badge/BlockchainCourse-21CY712-green)  ![](https://img.shields.io/badge/-M.Tech_Dissertation-blue) ![](https://img.shields.io/badge/Focus-Smart_Contract_Security-yellow) <br/>
![](https://img.shields.io/badge/Blockchain-Ethereum-blue)   <br/> 
![](https://img.shields.io/badge/Language-Solidity-blue)

## SOLIDITY_SAFEMATH
### Rule Description
<p>
    <code>SafeMath</code> library is used.
</p>

### Solidity-Rules

![](https://img.shields.io/badge/Pattern_ID-837cac-gold) ![](https://img.shields.io/badge/Severity-1-brown) 

```
usingForDeclaration[identifier[matches(text()[1], "^SafeMath$", "i")]]
```

### Sample Code

```
pragma solidity 0.4.24;

library SafeMath {
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }
}

contract MyToken {
    // <yes> <report> SOLIDITY_SAFEMATH 837cac
    using SafeMath for uint256;

    function sub(uint a, uint b) public returns(uint) {
        return(a.sub(b));
    }
}
```

### Abstract Syntax Tree 

[Click Here](https://astexplorer.net/#/gist/6d119342ef1d67adbea057d4787442cd/3e3ec2fdbe24bb0b1ae2d58e1a9a3b7465dd0f69) to view the AST for the above code. Code generated from AST Explorer using _solidity-parser-antlr-0.4.11_


### Code Result

```
SOLIDITY_SAFEMATH
patternId: 837cac
severity: 1
line: 12
column: 4
content: usingSafeMathforuint256;

SOLIDITY_SAFEMATH :1


```
