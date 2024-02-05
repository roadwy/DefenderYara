
rule VirTool_BAT_Injector_UD_bit{
	meta:
		description = "VirTool:BAT/Injector.UD!bit,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {23 00 72 00 65 00 73 00 6e 00 61 00 6d 00 65 00 23 00 90 02 30 23 00 70 00 61 00 73 00 73 00 23 00 90 00 } //01 00 
		$a_01_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 44 00 72 00 61 00 77 00 69 00 6e 00 67 00 2e 00 64 00 6c 00 6c 00 } //01 00 
		$a_01_2 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 4d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00 2e 00 64 00 6c 00 6c 00 } //01 00 
		$a_01_3 = {2f 00 6f 00 70 00 74 00 69 00 6d 00 69 00 7a 00 65 00 2b 00 20 00 2f 00 70 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00 3a 00 58 00 38 00 36 00 20 00 2f 00 64 00 65 00 62 00 75 00 67 00 2b 00 20 00 2f 00 74 00 61 00 72 00 67 00 65 00 74 00 3a 00 77 00 69 00 6e 00 65 00 78 00 65 00 } //01 00 
		$a_01_4 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 } //01 00 
		$a_01_5 = {00 52 65 70 6c 61 63 65 00 } //01 00 
		$a_01_6 = {00 43 6f 6d 70 69 6c 65 41 73 73 65 6d 62 6c 79 46 72 6f 6d 53 6f 75 72 63 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}