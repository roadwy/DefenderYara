
rule VirTool_Win64_Encledosz_A_MTB{
	meta:
		description = "VirTool:Win64/Encledosz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 7c 24 30 90 01 06 48 8b c8 90 01 05 48 8b f8 48 85 c0 90 01 06 48 8b d0 48 89 5c 24 48 90 02 12 33 c9 ba 00 10 00 00 44 8b c2 90 02 10 33 d2 41 b8 f8 0f 00 00 48 8b d8 90 00 } //1
		$a_03_1 = {48 c7 44 24 40 00 00 00 00 c7 03 10 00 00 00 c7 43 04 00 00 10 00 90 01 06 41 b9 08 00 00 00 4c 8b c3 48 8b c8 48 8b d7 90 01 05 48 89 44 24 20 90 01 06 48 8b d0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}