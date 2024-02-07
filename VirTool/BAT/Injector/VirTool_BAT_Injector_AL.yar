
rule VirTool_BAT_Injector_AL{
	meta:
		description = "VirTool:BAT/Injector.AL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 6f 0d 00 00 0a 80 04 00 00 04 7e 04 00 00 04 8e 69 80 03 00 00 04 06 } //01 00 
		$a_01_1 = {73 14 00 00 0a 26 18 17 1c 73 15 00 00 0a 0c 7e 16 00 00 0a 20 40 1f 00 00 } //01 00 
		$a_01_2 = {11 04 11 05 9a 26 03 05 06 17 58 6f 24 00 00 0a 0c 08 15 } //01 00 
		$a_00_3 = {65 6b 4c 78 49 48 71 76 7a 6b 45 61 74 72 6d 4b 4f 67 4a 67 } //00 00  ekLxIHqvzkEatrmKOgJg
	condition:
		any of ($a_*)
 
}