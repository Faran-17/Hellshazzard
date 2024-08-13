# HellsHazzard

A small POC to bypass NT API hooking using [@maldevacademy](https://maldevacademy.com/) indirect sycall technique.

The tool consists of the following features - 

1. HellsHall implementation of indirect syscall bypass by [@maldevacademy](https://maldevacademy.com/)
2. Mechanism to detect the presence of InetSim sandbox, if detected halts the execution of the malware.
3. API hashing.
4. IPv6 shellcode obfuscation.
5. IAT Obfuscation to evade static analysis.
6. Debugger check

Here are the screenshot and demo of the tool

## InetSim Detection
Before execution, the malware will check if the InetSim, which is a internet simulation sandox to trick malwares to continue to execute and make connection to the C2.

![image](https://github.com/user-attachments/assets/926f418b-8b20-436d-ab60-92cd0298d071)


## IAT Obfuscation
IAT Obfuscation hides the presence of malicious APIs in IAT table to evade basic static analysis. 

![image](https://github.com/user-attachments/assets/e625f677-0cba-4903-a0c5-8b6dfa9418d8)
 

## NT API Evasion
Using HellsHall indirect system calls which is a modified version of Tartarus gate logic to evade NT Api hooking by [@BestEdrOfTheMarket](https://github.com/Xacone/BestEdrOfTheMarket) EDR.  

https://github.com/user-attachments/assets/114bec4f-1770-42b0-a05b-34a03dcd78cb


Note - This tool is not tested against commercial EDRs and AV evasion and kernel base detection is out of the scope as well. New features and techniques will be implemented in other tools in near future.


