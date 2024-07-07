
rule VirTool_BAT_Injector_K{
	meta:
		description = "VirTool:BAT/Injector.K,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 66 68 6e 20 4d 18 22 76 b5 33 11 12 33 0c 6d 0a 20 4d 18 22 9e a1 29 61 1c 76 b5 05 19 01 58 } //1
		$a_01_1 = {46 75 63 6b 4a 61 67 65 78 2e 63 6f 6d 5f 73 5f 42 69 6e 64 65 72 5f 53 74 75 62 } //1 FuckJagex.com_s_Binder_Stub
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}