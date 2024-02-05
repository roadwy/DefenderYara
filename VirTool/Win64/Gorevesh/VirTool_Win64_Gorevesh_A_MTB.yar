
rule VirTool_Win64_Gorevesh_A_MTB{
	meta:
		description = "VirTool:Win64/Gorevesh.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 6f 52 65 76 65 72 73 65 53 68 65 6c 6c 54 4c 53 } //01 00 
		$a_03_1 = {48 89 4c 24 08 48 c7 44 24 10 03 00 00 00 48 8d 90 01 05 48 89 4c 24 18 48 c7 44 24 20 12 00 00 00 48 89 44 24 28 e8 90 00 } //01 00 
		$a_03_2 = {48 89 8c 24 d8 00 00 00 48 89 84 24 d0 00 00 00 c6 44 24 4f 01 48 8d 90 01 05 48 89 0c 24 48 c7 44 24 08 07 00 00 00 0f 57 c0 0f 11 44 24 10 48 c7 44 24 20 00 00 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}