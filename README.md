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

![image](https://github.com/user-attachments/assets/3efd2b00-d134-4f86-89ef-65a953891476)  

## IAT Obfuscation
IAT Obfuscation hides the presence of malicious APIs in IAT table to evade basic static analysis. 

![image](https://github.com/user-attachments/assets/f2d00e16-8a6a-489d-ba9f-6f38ef4d6bc5)   

## NT API Evasion
Using HellsHall indirect system calls which is a modified version of Tartarus gate logic to evade NT Api hooking by [@BestEdrOfTheMarket](https://github.com/Xacone/BestEdrOfTheMarket) EDR.  

https://github.com/user-attachments/assets/fc7cb7a9-a33f-4034-94f2-536241dd44ec  


Note - AV evasion and kernel base detection is out of the scope of this tool. New features and techniques will be implemented in other tools in near future.


