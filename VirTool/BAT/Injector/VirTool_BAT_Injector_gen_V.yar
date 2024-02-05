
rule VirTool_BAT_Injector_gen_V{
	meta:
		description = "VirTool:BAT/Injector.gen!V,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 6f 7a 43 77 5c 42 53 72 } //01 00 
		$a_01_1 = {53 49 4c 6c 7a 43 77 58 42 53 72 } //01 00 
		$a_01_2 = {47 00 65 00 74 00 54 00 79 00 70 00 65 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}