
rule VirTool_Win64_Kitez_A_MTB{
	meta:
		description = "VirTool:Win64/Kitez.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {66 89 44 24 36 48 89 4c 24 40 48 89 5c 24 38 48 8d 90 01 05 e8 90 01 04 48 c7 00 00 00 00 00 48 8b 5c 24 40 48 8d 90 01 05 48 89 c7 90 00 } //01 00 
		$a_02_1 = {48 89 d9 48 89 c3 48 8b 84 24 00 01 00 00 e8 90 01 04 66 89 44 24 2c 44 0f 11 7c 24 53 90 00 } //01 00 
		$a_02_2 = {48 83 ec 08 48 89 2c 24 48 8d 2c 24 e8 90 01 04 84 c0 75 27 0f 1f 44 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}