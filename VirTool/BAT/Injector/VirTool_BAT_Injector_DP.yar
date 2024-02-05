
rule VirTool_BAT_Injector_DP{
	meta:
		description = "VirTool:BAT/Injector.DP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 72 6f 6d 65 31 2e 65 78 65 } //01 00 
		$a_01_1 = {76 66 75 63 6b } //01 00 
		$a_01_2 = {69 6e 76 6f 6b 6d 79 61 } //00 00 
	condition:
		any of ($a_*)
 
}