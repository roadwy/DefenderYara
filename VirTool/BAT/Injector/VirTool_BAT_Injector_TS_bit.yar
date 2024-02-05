
rule VirTool_BAT_Injector_TS_bit{
	meta:
		description = "VirTool:BAT/Injector.TS!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {84 95 d7 6e 20 ff 00 00 00 6a 5f b7 95 8c 1a 00 00 01 28 2a 00 00 0a 28 2b 00 00 0a 9c 11 07 17 d6 13 07 } //01 00 
		$a_01_1 = {0d 4c 00 65 00 6e 00 67 00 74 00 68 00 } //01 00 
		$a_01_2 = {53 75 62 74 72 61 63 74 4f 62 6a 65 63 74 00 54 6f 49 6e 74 65 67 65 72 00 4d 6f 64 4f 62 6a 65 63 74 00 41 64 64 4f 62 6a 65 63 74 00 41 6e 64 4f 62 6a 65 63 74 00 54 6f 55 49 6e 74 65 67 65 72 00 58 6f 72 4f 62 6a 65 63 74 00 54 6f 42 79 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}