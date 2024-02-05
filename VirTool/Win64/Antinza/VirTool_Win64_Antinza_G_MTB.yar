
rule VirTool_Win64_Antinza_G_MTB{
	meta:
		description = "VirTool:Win64/Antinza.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 74 68 65 6e 61 2e 4d 6f 64 65 6c 73 2e 43 6f 6d 6d 73 2e 53 4d 42 } //01 00 
		$a_81_1 = {41 74 68 65 6e 61 2e 48 61 6e 64 6c 65 72 2e 44 79 6e 61 6d 69 63 } //01 00 
		$a_81_2 = {41 74 68 65 6e 61 2e 4d 6f 64 65 6c 73 2e 43 6f 6e 66 69 67 } //01 00 
		$a_81_3 = {41 74 68 65 6e 61 2e 43 6f 6d 6d 61 6e 64 73 } //01 00 
		$a_81_4 = {41 74 68 65 6e 61 2e 4d 6f 64 65 6c 73 2e 4d 79 74 68 69 63 2e 43 68 65 63 6b 69 6e } //01 00 
		$a_81_5 = {41 74 68 65 6e 61 2e 55 74 69 6c 69 74 69 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}