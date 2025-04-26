
rule HackTool_Win64_InjectSvc_A{
	meta:
		description = "HackTool:Win64/InjectSvc.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 72 65 61 74 69 6e 67 20 72 65 6d 6f 74 65 20 74 68 72 65 61 64 20 2d 20 46 72 65 65 4c 69 62 72 61 72 79 } //1 creating remote thread - FreeLibrary
		$a_01_1 = {49 6e 6a 65 63 74 48 6f 6f 6b 20 72 65 74 75 72 6e 65 64 20 25 64 } //1 InjectHook returned %d
		$a_01_2 = {61 64 6a 75 73 74 65 64 20 53 65 44 65 62 75 67 50 72 69 76 69 6c 69 67 65 } //1 adjusted SeDebugPrivilige
		$a_01_3 = {6f 70 65 6e 69 6e 67 20 70 72 6f 63 65 73 73 } //1 opening process
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}