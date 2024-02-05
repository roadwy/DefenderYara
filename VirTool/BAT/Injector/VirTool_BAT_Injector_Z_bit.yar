
rule VirTool_BAT_Injector_Z_bit{
	meta:
		description = "VirTool:BAT/Injector.Z!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 58 47 61 d2 52 90 01 01 17 58 90 09 10 00 d3 90 01 01 58 90 01 01 d3 90 01 01 58 47 90 01 01 d3 90 01 01 7e 90 01 01 00 00 04 90 00 } //01 00 
		$a_03_1 = {6f 3a 00 00 0a 5d 58 47 61 d2 52 90 01 01 17 58 90 09 10 00 d3 90 01 01 58 90 01 01 d3 90 01 01 58 47 90 01 01 d3 90 01 01 7e 90 01 01 00 00 04 90 00 } //02 00 
		$a_00_2 = {53 00 54 79 70 65 00 47 54 00 4b } //00 00 
	condition:
		any of ($a_*)
 
}