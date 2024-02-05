
rule VirTool_BAT_Asemlod_B{
	meta:
		description = "VirTool:BAT/Asemlod.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 07 19 5a 18 58 12 90 01 01 28 90 01 03 06 9c 06 07 19 5a 17 58 12 90 01 01 28 90 01 03 06 9c 06 07 19 5a 12 90 01 01 28 90 01 03 06 9c 07 17 58 90 00 } //01 00 
		$a_03_1 = {19 d8 18 d6 12 90 01 01 28 90 01 04 9c 09 11 90 01 01 19 d8 17 d6 12 90 01 01 28 90 01 04 9c 09 11 90 01 01 19 d8 12 90 01 01 28 90 01 04 9c 11 90 01 01 17 d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}