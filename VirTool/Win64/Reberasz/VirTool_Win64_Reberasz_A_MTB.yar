
rule VirTool_Win64_Reberasz_A_MTB{
	meta:
		description = "VirTool:Win64/Reberasz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 b9 08 00 00 00 90 01 07 48 8b c8 90 02 10 8b d0 90 02 12 4c 8b 0d 2a 40 00 00 90 01 05 48 89 44 24 28 90 01 07 ba 00 10 00 00 89 7c 24 20 33 c9 89 7c 24 30 90 01 06 b9 e8 03 00 00 90 00 } //01 00 
		$a_03_1 = {48 c7 44 24 58 12 00 14 00 48 89 44 24 60 90 01 09 48 c7 45 b8 30 00 00 00 48 89 45 c8 90 01 07 48 8b 44 24 38 0f 57 c0 45 33 c9 48 89 45 c0 ba 00 00 00 10 48 c7 45 d0 40 00 00 00 f3 0f 7f 45 d8 48 89 7c 24 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}