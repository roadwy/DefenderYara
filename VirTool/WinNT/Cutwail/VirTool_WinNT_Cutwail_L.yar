
rule VirTool_WinNT_Cutwail_L{
	meta:
		description = "VirTool:WinNT/Cutwail.L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {75 05 8b 45 08 eb 1b 8b 45 08 33 d2 f7 75 0c 89 45 fc 8b 45 fc 83 c0 01 89 45 fc 8b 45 fc } //02 00 
		$a_01_1 = {68 52 57 4e 44 8b 45 f8 50 6a 00 } //01 00 
		$a_01_2 = {e9 5c ff ff ff 8b 45 fc 8b 4d 0c 89 48 34 } //01 00 
		$a_03_3 = {0f 32 89 45 f0 83 7d f0 00 75 90 01 01 0f 01 4d 90 00 } //01 00 
		$a_01_4 = {68 e8 d8 02 9a 68 5d 33 78 df } //01 00 
		$a_01_5 = {0f b6 02 3d ff 00 00 00 75 1c 8b 4d f4 0f b6 51 01 83 fa 25 75 10 } //00 00 
	condition:
		any of ($a_*)
 
}