
rule VirTool_BAT_PoshC2_D{
	meta:
		description = "VirTool:BAT/PoshC2.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 61 66 64 73 76 33 32 00 73 61 66 64 73 76 36 34 00 } //01 00 
		$a_01_1 = {4f 62 6a 65 63 74 00 69 6e 6a 65 63 74 00 } //01 00 
		$a_01_2 = {50 41 47 45 5f 45 58 45 43 55 54 45 5f 52 45 41 44 57 52 49 54 45 00 } //01 00 
		$a_01_3 = {5c 50 6f 73 68 43 32 5f 44 4c 4c 53 5c 44 6f 74 4e 65 74 32 4a 53 5c 44 6f 74 4e 65 74 32 4a 53 5c } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_BAT_PoshC2_D_2{
	meta:
		description = "VirTool:BAT/PoshC2.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 57 5f 48 49 44 45 00 52 75 6e 43 53 00 53 57 5f 53 48 4f 57 00 } //01 00 
		$a_03_1 = {50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 90 02 04 53 00 68 00 61 00 72 00 70 00 90 00 } //01 00 
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 00 42 69 6e 64 65 72 } //01 00 
		$a_01_3 = {5c 50 6f 73 68 43 32 5f 44 4c 4c 73 5c 53 68 61 72 70 52 75 6e 6e 65 72 5c 53 68 61 72 70 52 75 6e 6e 65 72 5c } //00 00 
	condition:
		any of ($a_*)
 
}