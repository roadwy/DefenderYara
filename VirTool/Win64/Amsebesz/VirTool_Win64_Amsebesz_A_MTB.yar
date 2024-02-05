
rule VirTool_Win64_Amsebesz_A_MTB{
	meta:
		description = "VirTool:Win64/Amsebesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b c8 48 8d 94 90 01 05 ff 15 90 01 04 48 8b f0 48 8d 94 90 01 05 0f b6 8c 24 00 01 00 00 84 c9 74 90 00 } //01 00 
		$a_03_1 = {48 89 84 24 98 00 00 00 48 8d 84 90 01 05 48 89 44 24 20 45 90 01 03 4c 8d 84 90 01 05 48 8d 94 90 01 05 49 8b ce ff 15 90 00 } //01 00 
		$a_03_2 = {4c 89 7c 24 20 41 b9 01 00 00 00 4c 8d 84 90 01 05 48 8b d0 49 8b ce ff 15 90 00 } //01 00 
		$a_03_3 = {48 8b 0c cb ff 15 90 01 04 44 8b c0 33 d2 8d 90 01 02 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}