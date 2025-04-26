
rule Trojan_Win64_ShellcodeRunner_PKZ_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.PKZ!MTB,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_01_0 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //2 explorer.exe
		$a_01_1 = {41 6c 6c 6f 63 61 74 65 20 6d 65 6d 6f 72 79 20 53 75 63 63 65 73 73 } //2 Allocate memory Success
		$a_01_2 = {46 61 69 6c 65 64 20 74 6f 20 77 72 69 74 65 20 73 68 65 6c 6c 63 6f 64 65 20 74 6f 20 6d 65 6d 6f 72 79 } //2 Failed to write shellcode to memory
		$a_01_3 = {49 6e 6a 65 63 74 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //2 Inject successfully
		$a_01_4 = {47 6f 74 20 68 61 6e 64 6c 65 20 74 6f 20 74 68 72 65 61 64 } //1 Got handle to thread
		$a_01_5 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_6 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 57 } //1 Process32FirstW
		$a_01_7 = {47 6c 6f 62 61 6c 4d 65 6d 6f 72 79 53 74 61 74 75 73 45 78 } //1 GlobalMemoryStatusEx
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=12
 
}