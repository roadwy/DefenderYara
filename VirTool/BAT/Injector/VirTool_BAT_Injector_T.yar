
rule VirTool_BAT_Injector_T{
	meta:
		description = "VirTool:BAT/Injector.T,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 07 02 07 91 03 07 06 5d 91 61 28 90 01 01 00 00 0a 9c 07 17 58 0b 07 02 8e 69 32 e5 90 00 } //01 00 
		$a_03_1 = {d3 58 4b 20 00 30 00 00 1f 40 6f 90 01 01 00 00 06 7e 90 01 01 00 00 0a 28 90 01 01 00 00 0a 2c 09 90 00 } //01 00 
		$a_03_2 = {13 06 1f 28 8d 90 01 01 00 00 01 13 07 20 f8 00 00 00 8d 90 01 01 00 00 01 13 08 1f 40 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}