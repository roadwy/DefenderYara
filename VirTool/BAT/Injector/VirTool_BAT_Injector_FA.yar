
rule VirTool_BAT_Injector_FA{
	meta:
		description = "VirTool:BAT/Injector.FA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {16 0c 2b 0f 06 07 06 07 91 03 08 91 61 d2 9c 08 17 58 0c 08 03 8e 69 32 eb } //01 00 
		$a_03_1 = {1f 27 9a 13 90 01 01 11 90 01 01 14 17 8d 01 00 00 01 13 90 01 01 11 90 01 01 16 11 04 a2 11 90 01 01 6f 90 01 01 00 00 0a 74 90 01 01 00 00 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}