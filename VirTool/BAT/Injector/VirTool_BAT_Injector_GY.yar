
rule VirTool_BAT_Injector_GY{
	meta:
		description = "VirTool:BAT/Injector.GY,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 af 7e 1d 00 00 0a 13 06 7e 1d 00 00 0a 08 8e 69 20 00 30 00 00 1f 40 28 0a 00 00 06 13 06 08 16 11 06 08 8e 69 28 20 00 00 0a 11 06 d0 05 00 00 02 } //00 00 
	condition:
		any of ($a_*)
 
}