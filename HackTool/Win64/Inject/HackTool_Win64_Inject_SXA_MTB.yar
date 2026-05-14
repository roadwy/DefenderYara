
rule HackTool_Win64_Inject_SXA_MTB{
	meta:
		description = "HackTool:Win64/Inject.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 63 65 73 73 20 69 6e 6a 65 63 74 69 6f 6e 20 28 44 4c 4c 20 69 6e 6a 65 63 74 69 6f 6e 29 } //5 Process injection (DLL injection)
		$a_01_1 = {49 6e 6a 65 63 74 69 6f 6e 20 73 75 63 63 65 73 73 66 75 6c 21 } //5 Injection successful!
		$a_01_2 = {74 6f 6b 65 6e 20 74 68 65 66 74 } //2 token theft
		$a_01_3 = {41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 73 74 65 61 6c 20 53 59 53 54 45 4d 20 74 6f 6b 65 6e 20 66 72 6f 6d 20 77 69 6e 6c 6f 67 6f 6e 2e 65 78 65 } //2 Attempting to steal SYSTEM token from winlogon.exe
		$a_01_4 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 69 6d 70 65 72 73 6f 6e 61 74 69 6e 67 20 53 59 53 54 45 4d 21 } //1 Successfully impersonating SYSTEM!
		$a_01_5 = {50 72 6f 63 65 73 73 20 69 73 20 72 75 6e 6e 69 6e 67 20 77 69 74 68 20 65 6c 65 76 61 74 65 64 20 70 72 69 76 69 6c 65 67 65 73 } //1 Process is running with elevated privileges
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=16
 
}