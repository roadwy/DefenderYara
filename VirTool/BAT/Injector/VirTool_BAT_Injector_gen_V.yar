
rule VirTool_BAT_Injector_gen_V{
	meta:
		description = "VirTool:BAT/Injector.gen!V,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 7a 43 77 5c 42 53 72 } //1 LozCw\BSr
		$a_01_1 = {53 49 4c 6c 7a 43 77 58 42 53 72 } //1 SILlzCwXBSr
		$a_01_2 = {47 00 65 00 74 00 54 00 79 00 70 00 65 00 73 00 } //1 GetTypes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}