
rule VirTool_WinNT_Cutwail_K{
	meta:
		description = "VirTool:WinNT/Cutwail.K,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 09 00 00 02 00 "
		
	strings :
		$a_03_0 = {73 54 8b 55 08 03 55 fc 0f b6 02 83 f0 90 01 01 8b 4d 08 03 4d fc 88 01 8b 55 08 03 55 fc 0f b6 42 01 83 f0 90 00 } //02 00 
		$a_03_1 = {68 52 57 4e 44 8b 4d e4 51 8b 55 14 52 ff 15 90 01 04 89 45 f0 83 7d f0 00 74 1b 90 00 } //02 00 
		$a_01_2 = {75 05 8b 45 08 eb 1b 8b 45 08 33 d2 f7 75 0c 89 45 fc 8b 45 fc } //02 00 
		$a_03_3 = {73 39 8b 4d fc 81 c1 90 01 04 89 4d f8 8b 55 f8 81 3a 05 a1 55 f3 75 20 90 00 } //02 00 
		$a_03_4 = {7c 1f 8b 55 0c 52 a1 90 01 04 8b 4d fc 03 08 51 e8 90 01 04 83 c4 08 85 c0 75 04 c6 45 f7 01 90 00 } //02 00 
		$a_01_5 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 50 00 72 00 6f 00 74 00 33 00 00 00 } //01 00 
		$a_01_6 = {70 72 6f 74 65 63 74 2e 70 64 62 00 } //01 00 
		$a_01_7 = {49 6e 6e 65 72 44 72 76 2e 70 64 62 00 } //01 00 
		$a_01_8 = {63 49 60 00 7f 52 62 47 7d 41 73 00 7e 41 7f 4e } //00 00  䥣`剿䝢䅽s䅾乿
	condition:
		any of ($a_*)
 
}