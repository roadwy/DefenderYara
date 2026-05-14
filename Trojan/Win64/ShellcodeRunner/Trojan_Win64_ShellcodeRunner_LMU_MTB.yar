
rule Trojan_Win64_ShellcodeRunner_LMU_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.LMU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_81_0 = {5b 2b 5d 20 73 79 73 5a 77 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 20 65 78 65 63 75 74 65 64 } //1 [+] sysZwAllocateVirtualMemory executed
		$a_81_1 = {5b 2b 5d 20 73 79 73 4e 74 50 72 6f 74 65 63 74 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 20 65 78 65 63 75 74 65 64 } //2 [+] sysNtProtectVirtualMemory executed
		$a_81_2 = {5b 2b 5d 20 73 79 73 4e 74 43 72 65 61 74 65 54 68 72 65 61 64 45 78 20 65 78 65 63 75 74 65 64 } //3 [+] sysNtCreateThreadEx executed
		$a_81_3 = {5d 20 46 61 69 6c 65 64 20 69 6e 20 73 79 73 4e 74 57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 20 28 25 75 29 } //4 ] Failed in sysNtWaitForSingleObject (%u)
		$a_81_4 = {5b 2b 5d 20 73 79 73 4e 74 57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 20 65 78 65 63 75 74 65 64 } //5 [+] sysNtWaitForSingleObject executed
		$a_81_5 = {5b 2b 5d 20 46 69 6e 69 73 68 65 64 } //6 [+] Finished
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*3+(#a_81_3  & 1)*4+(#a_81_4  & 1)*5+(#a_81_5  & 1)*6) >=21
 
}