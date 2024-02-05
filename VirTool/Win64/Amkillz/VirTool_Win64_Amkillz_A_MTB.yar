
rule VirTool_Win64_Amkillz_A_MTB{
	meta:
		description = "VirTool:Win64/Amkillz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {c6 45 12 48 c6 45 13 3f c6 45 14 3f c6 45 15 3f c6 45 16 3f c6 45 17 74 c6 45 18 33 c7 45 34 11 00 00 00 } //01 00 
		$a_02_1 = {48 8b 85 b8 00 00 00 48 89 44 24 20 44 8b 4d 34 4c 8d 90 01 02 ba 00 04 00 00 48 8d 90 01 05 e8 90 00 } //01 00 
		$a_00_2 = {8b 45 04 48 8b 8d 20 01 00 00 0f b6 04 01 b9 01 00 00 00 48 6b c9 00 48 8b 95 30 01 00 00 0f b6 0c 0a 3b c1 } //01 00 
		$a_02_3 = {48 c7 44 24 20 00 00 00 00 41 b9 01 00 00 00 4c 8d 90 01 05 48 8b 95 18 05 00 00 48 8b 4d 78 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}