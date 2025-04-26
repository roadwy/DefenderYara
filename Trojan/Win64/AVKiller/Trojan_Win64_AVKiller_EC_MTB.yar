
rule Trojan_Win64_AVKiller_EC_MTB{
	meta:
		description = "Trojan:Win64/AVKiller.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {45 76 69 6c 42 79 74 65 63 6f 64 65 2f 47 6f 44 65 66 65 6e 64 65 72 2f 41 6e 74 69 44 65 62 75 67 2f 43 68 65 63 6b 42 6c 61 63 6b 6c 69 73 74 65 64 57 69 6e 64 6f 77 73 4e 61 6d 65 73 2e 69 6e 69 74 } //1 EvilBytecode/GoDefender/AntiDebug/CheckBlacklistedWindowsNames.init
		$a_81_1 = {45 76 69 6c 42 79 74 65 63 6f 64 65 2f 47 6f 44 65 66 65 6e 64 65 72 2f 41 6e 74 69 44 65 62 75 67 2f 49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 2e 49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 31 } //1 EvilBytecode/GoDefender/AntiDebug/IsDebuggerPresent.IsDebuggerPresent1
		$a_81_2 = {41 6e 74 69 44 65 62 75 67 2f 4b 69 6c 6c 42 61 64 50 72 6f 63 65 73 73 65 73 2f 4b 69 6c 6c 42 61 64 50 72 6f 63 65 73 73 65 73 2e 67 6f } //1 AntiDebug/KillBadProcesses/KillBadProcesses.go
		$a_81_3 = {41 6e 74 69 56 69 72 74 75 61 6c 69 7a 61 74 69 6f 6e 2f 55 73 65 72 6e 61 6d 65 43 68 65 63 6b 2f 55 73 65 72 6e 61 6d 65 43 68 65 63 6b 2e 67 6f } //1 AntiVirtualization/UsernameCheck/UsernameCheck.go
		$a_81_4 = {41 6e 74 69 56 69 72 74 75 61 6c 69 7a 61 74 69 6f 6e 2f 56 4d 57 61 72 65 44 65 74 65 63 74 69 6f 6e 2f 76 6d 77 61 72 65 64 65 74 65 63 74 69 6f 6e 2e 67 6f } //1 AntiVirtualization/VMWareDetection/vmwaredetection.go
		$a_81_5 = {41 6e 74 69 56 69 72 74 75 61 6c 69 7a 61 74 69 6f 6e 2f 56 69 72 74 75 61 6c 62 6f 78 44 65 74 65 63 74 69 6f 6e 2f 76 69 72 74 75 61 6c 62 6f 78 64 65 74 65 63 74 69 6f 6e 2e 67 6f } //1 AntiVirtualization/VirtualboxDetection/virtualboxdetection.go
		$a_81_6 = {4d 61 69 6e 47 6f 2f 61 64 72 2e 67 6f } //1 MainGo/adr.go
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}