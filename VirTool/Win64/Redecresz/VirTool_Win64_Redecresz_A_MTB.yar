
rule VirTool_Win64_Redecresz_A_MTB{
	meta:
		description = "VirTool:Win64/Redecresz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 85 8b 00 00 00 48 8d 90 01 05 ff 15 90 01 04 48 85 c0 0f 84 a4 00 00 00 48 8d 90 01 05 48 8b c8 ff 15 90 01 04 48 89 05 b6 c2 00 00 48 85 c0 74 42 48 8d 90 00 } //01 00 
		$a_03_1 = {48 89 85 40 01 00 00 4c 89 4c 24 58 45 8b e8 4c 8b e2 44 8b f9 4c 8b b5 c0 01 00 00 48 8b b5 c8 01 00 00 48 8b bd d0 01 00 00 48 8b 85 d8 01 00 00 48 89 44 24 50 48 8b 9d e0 01 00 00 48 8d 90 01 05 ff 15 90 00 } //01 00 
		$a_03_2 = {85 d2 75 2b e8 90 01 04 ff 15 90 01 04 48 8b c8 e8 90 01 04 48 8d 90 01 05 48 8d 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}