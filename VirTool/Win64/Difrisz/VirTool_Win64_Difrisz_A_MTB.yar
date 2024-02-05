
rule VirTool_Win64_Difrisz_A_MTB{
	meta:
		description = "VirTool:Win64/Difrisz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {45 8b e5 41 8b dd 48 89 5d cf 45 8b fd 44 89 6c 24 20 45 33 c9 45 33 c0 33 d2 48 8d 90 01 05 ff 15 90 01 04 48 8b f0 48 89 90 00 } //01 00 
		$a_03_1 = {48 89 7e 18 48 8b cb 4c 90 01 03 49 03 c6 4c 90 01 03 48 83 fd 08 72 59 48 8b 3e 48 8b d7 e8 90 01 04 4d 8b c7 49 8b d5 49 8b cc e8 90 01 04 33 c0 48 8d 14 90 01 05 66 41 89 06 48 81 90 00 } //01 00 
		$a_03_2 = {48 8b 78 50 48 8b 8d 20 01 00 00 48 8b 95 28 01 00 00 48 8b c2 48 2b c1 48 3b f8 77 35 48 90 01 03 48 89 85 20 01 00 00 48 8d 90 01 05 48 83 fa 10 48 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}