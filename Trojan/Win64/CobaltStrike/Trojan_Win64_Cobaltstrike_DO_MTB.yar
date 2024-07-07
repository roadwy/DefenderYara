
rule Trojan_Win64_Cobaltstrike_DO_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c3 41 2a c5 24 08 32 03 40 32 c7 88 03 49 03 df 48 3b dd 72 } //1
		$a_81_1 = {69 6e 67 61 6d 65 72 75 73 68 2e 64 6c 6c } //1 ingamerush.dll
		$a_81_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_4 = {43 72 65 61 74 65 46 69 6c 65 57 } //1 CreateFileW
		$a_81_5 = {57 72 69 74 65 46 69 6c 65 } //1 WriteFile
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}