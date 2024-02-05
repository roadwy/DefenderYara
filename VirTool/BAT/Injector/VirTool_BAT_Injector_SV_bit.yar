
rule VirTool_BAT_Injector_SV_bit{
	meta:
		description = "VirTool:BAT/Injector.SV!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 00 33 00 56 00 68 00 64 00 57 00 4e 00 73 00 64 00 43 00 51 00 3d 00 } //01 00 
		$a_01_1 = {5c 77 6d 70 6e 65 74 77 6b 5c 77 6d 70 6e 65 74 77 6b } //01 00 
		$a_01_2 = {5f 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 24 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_BAT_Injector_SV_bit_2{
	meta:
		description = "VirTool:BAT/Injector.SV!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 53 75 62 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_1 = {46 00 4c 00 69 00 62 00 2e 00 46 00 4c 00 69 00 62 00 } //01 00 
		$a_03_2 = {06 08 06 8e b7 5d 91 61 02 08 17 d6 02 8e b7 5d 91 da 20 90 01 04 d6 20 90 01 04 5d b4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_BAT_Injector_SV_bit_3{
	meta:
		description = "VirTool:BAT/Injector.SV!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6e 6a 65 63 74 69 6f 6e 45 6e 75 6d } //01 00 
		$a_03_1 = {76 00 62 00 63 00 2e 00 65 00 78 00 65 00 90 02 10 52 00 65 00 67 00 41 00 73 00 6d 00 2e 00 65 00 78 00 65 00 90 02 10 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_01_2 = {43 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 54 00 4e 00 20 00 22 00 55 00 70 00 64 00 61 00 74 00 65 00 } //01 00 
		$a_01_3 = {3a 00 5a 00 4f 00 4e 00 45 00 2e 00 69 00 64 00 65 00 6e 00 74 00 69 00 66 00 69 00 65 00 72 00 20 00 26 00 20 00 65 00 78 00 69 00 74 00 } //01 00 
		$a_01_4 = {03 09 03 8e 69 5d 91 61 02 09 17 d6 02 8e 69 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 09 17 d6 0d } //00 00 
	condition:
		any of ($a_*)
 
}