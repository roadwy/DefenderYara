
rule VirTool_BAT_Injector_HY{
	meta:
		description = "VirTool:BAT/Injector.HY,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 6e 64 6d 6b 65 79 } //01 00 
		$a_01_1 = {53 63 72 69 62 65 } //01 00 
		$a_01_2 = {42 6f 74 6b 69 6c 6c } //01 00 
		$a_01_3 = {4b 69 6c 6c 41 6e 64 44 65 6c 65 74 65 } //01 00 
		$a_01_4 = {45 72 61 73 65 53 } //00 00 
		$a_00_5 = {5d 04 00 } //00 15 
	condition:
		any of ($a_*)
 
}