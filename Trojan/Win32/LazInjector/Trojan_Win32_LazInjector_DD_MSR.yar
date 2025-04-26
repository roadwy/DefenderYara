
rule Trojan_Win32_LazInjector_DD_MSR{
	meta:
		description = "Trojan:Win32/LazInjector.DD!MSR,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 49 6e 74 65 6c 5c 74 6d 70 33 41 43 2e 74 6d 70 } //1 C:\Intel\tmp3AC.tmp
		$a_01_1 = {49 6e 6a 65 63 74 69 6f 6e 20 3a 20 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 20 46 61 69 6c 65 64 } //1 Injection : WriteProcessMemory Failed
		$a_01_2 = {49 6e 6a 65 63 74 69 6f 6e 20 3a 20 53 75 63 63 65 65 64 } //1 Injection : Succeed
		$a_01_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_4 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_01_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_01_6 = {50 61 74 68 46 69 6c 65 45 78 69 73 74 73 41 } //1 PathFileExistsA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}