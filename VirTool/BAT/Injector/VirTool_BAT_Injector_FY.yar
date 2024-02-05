
rule VirTool_BAT_Injector_FY{
	meta:
		description = "VirTool:BAT/Injector.FY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b 0f 06 07 06 07 91 03 08 91 61 d2 9c 08 17 58 0c 08 03 8e 69 32 eb } //01 00 
		$a_03_1 = {32 e8 12 02 7e 90 01 04 28 90 01 04 28 90 01 04 13 04 11 04 1f 27 90 00 } //01 00 
		$a_01_2 = {32 e6 06 17 58 0a 06 02 50 8e 69 32 d7 } //00 00 
	condition:
		any of ($a_*)
 
}