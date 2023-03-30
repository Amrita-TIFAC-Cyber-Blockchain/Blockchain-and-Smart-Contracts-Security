# Analysis of Smart Contract Security Vulnerabilities and Tools ![](https://img.shields.io/badge/-Live-brightgreen)

## Integrated Tool
![](https://www.ziion.org/logo-footer.svg) <br/>
- [Ziion](Tools/Ziion.md)

## Security Tools

### Detection

| Tool Name |   Status  |     Type   | Rule Based | Blockchain |
|-----------|:---------:|:----------:|:----------:|:----------:|
| [Etheno](Tools/Etheno.md) | | | SA, DA | ![](https://img.shields.io/badge/-Ethereum-gold) |
| ![](https://img.shields.io/badge/-Ziion-red) [Mythril](Tools/Mythril.md) | ![](https://img.shields.io/badge/-Live-brightgreen) | Static (CLI) | DSL | ![](https://img.shields.io/badge/-Ethereum-gold) ![](https://img.shields.io/badge/-Fabric-brown) | 
| [Mythx](Tools/Mythx.md) | ![](https://img.shields.io/badge/-Live-brightgreen) | (CLI/Web) | SA, SE, FT | ![](https://img.shields.io/badge/-Ethereum-gold) |
| [Oyente](Tools/Oyente.md) | ![](https://img.shields.io/badge/-Outdated-red) | Static (CLI) | Hardcorded Rules | ![](https://img.shields.io/badge/-Ethereum-gold) |
| [Tenderly](Tools/Tenderly.md) | ![](https://img.shields.io/badge/-Live-brightgreen) | Dynamic (CLI/Web) | SA, DA | ![](https://img.shields.io/badge/-Ethereum-gold) |
| ![](https://img.shields.io/badge/-Ziion-red) [Manticore](Tools/Manticore.md) | ![](https://img.shields.io/badge/-Live-brightgreen) | (CLI)| DSL | ![](https://img.shields.io/badge/-Ethereum-gold) ![](https://img.shields.io/badge/-Fabric-brown) | 
| ![](https://img.shields.io/badge/-Ziion-red) [Slither](Tools/Slither.md) | ![](https://img.shields.io/badge/-Live-brightgreen) | Static (CLI) | DSL | ![](https://img.shields.io/badge/-Ethereum-gold) ![](https://img.shields.io/badge/-Fabric-brown) | 
| [Piet](Tools/Piet.md) | ![](https://img.shields.io/badge/-Live-brightgreen) | Visualizer (Web) |
| [Smart Check](Tools/SmartCheck.md) | | Static (Web) | YAML | ![](https://img.shields.io/badge/-Ethereum-gold) ![](https://img.shields.io/badge/-Fabric-brown) | 
| [Vertigo](Tools/Vertigo.md) | ![](https://img.shields.io/badge/-Live-brightgreen) | Static (CLI) |
| [Solidity Visual Auditor](Tools/SolVisualAuditor.md) | ![](https://img.shields.io/badge/-Live-brightgreen) | Lint (Desktop-UI) |
| ![](https://img.shields.io/badge/-Ziion-red) [Solgraph](Tools/Solgraph.md) | | Visualizer (CLI) |
| [MPro](Tools/MPro.md) | ![](https://img.shields.io/badge/-Not_in_Use-red) | Static |
| [Securify](Tools/Securify.md) | | Static | |  ![](https://img.shields.io/badge/-Ethereum-gold) |
| [Hyperledger Caliper](Tools/Caliper.md) | | Static |   | ![](https://img.shields.io/badge/-Fabric-brown) | 
| [NeuCheck](Tools/NeuCheck.md) |  | | | 
| [Surya](Tools/Surya.md) | | | | 
| [Gas Gauge](Tools/GasGauge.md) | | | | 
| [Zeus](Tools/Zeus.md) | | | | 
| [WANA]() |  | | | ![](https://img.shields.io/badge/-EOSIO-silver) | 
| [ESCORT]() | | Deep Learning and Transfer Learning | | | 
| [ETBMC]() | | Bounded Model Checking | | | 
| [TeEther]() | | | | | 
| [ContractWard]() | | Machine Learning | | | 
| ConFuzzius | | Fuzzer | | ![](https://img.shields.io/badge/-Ethereum-gold) |
| Conkas | | Static, Symbolic Execution |  | ![](https://img.shields.io/badge/-Ethereum-gold) | 
| eThor | | Static | | |
| Pakala | | Symbolic Execution | | |

### Patching

| Tool Name |   Status  |     Type   | Rule Based | Blockchain |
|-----------|:---------:|:----------:|:----------:|:----------:|
| EVMPatch | | | | |

## Security Tools - Rule Definition Language

| Tool Name | Rule Language  | 
|-----------|:--------------:|
| [Mythril](Tools/Mythril.md) | Mythril-L |
| [Slither](Tools/Slither.md) | S-RDL |
| [Manticore](Tools/Manticore.md) | Manticore Language (MCL) |

## Frameworks

| Framework Name | Status | Tools used | Methodology  | Link | 
|:--------------:|:------:|:----------:|:------------:|:----:|
| ScrawlD |  | Slither, Mythril, Smartcheck, Oyente, Osiris |  | [ScrawlD](https://github.com/ramagururadhakrishnan/ScrawlD) |
| SmartBugs |  | ConFuzzius, Conkas, Ethainter, eThor, HoneyBadger, <br/> MadMax, Maian, Manticore, Mythril, Osiris <br/> Oyente, Pakala, Securify, sFuzz, Slither, <br/> Smartcheck, Solhint, teEther, Vandal | | [SmartBugs](https://github.com/ramagururadhakrishnan/smartbugs) |
| Vulpedia |  | Slither, Smartcheck, Oyente | |  | 

