
rule VirTool_BAT_Injector_gen_W{
	meta:
		description = "VirTool:BAT/Injector.gen!W,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 6e 74 69 44 65 62 75 67 67 65 72 00 61 6e 74 69 45 6d 75 6c 61 74 6f 72 } //01 00 
		$a_01_1 = {61 6e 74 69 52 65 67 4d 6f 6e 00 61 6e 74 69 53 61 6e 64 62 6f 78 69 65 } //01 00 
		$a_01_2 = {66 61 6b 65 45 72 72 6f 72 00 66 61 6b 65 45 72 72 6f 72 54 69 74 6c 65 } //01 00 
		$a_01_3 = {64 69 73 61 62 6c 65 46 69 72 65 77 61 6c 6c 00 64 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 } //01 00 
		$a_01_4 = {19 41 00 75 00 64 00 69 00 6f 00 20 00 44 00 65 00 76 00 69 00 63 00 65 00 00 1d 47 00 72 00 61 00 70 00 68 00 69 00 63 } //02 00 
		$a_01_5 = {02 08 07 6f 08 00 00 0a 13 04 12 04 28 09 00 00 0a 0d 09 2c 0d 06 09 28 0a 00 00 0a 6f 0b 00 00 0a 26 08 17 58 0c 08 02 6f 0c 00 00 0a 32 d1 } //01 00 
	condition:
		any of ($a_*)
 
}