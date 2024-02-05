
rule VirTool_WinNT_Vefisi_H{
	meta:
		description = "VirTool:WinNT/Vefisi.H,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 04 00 "
		
	strings :
		$a_03_0 = {53 79 73 74 65 6d 00 56 33 f6 8b 44 24 08 6a 06 03 c6 50 68 00 03 01 00 ff 15 90 01 02 01 00 83 c4 0c 85 c0 74 0f 46 81 fe 00 10 00 00 72 dc 90 00 } //01 00 
		$a_01_1 = {53 69 7a 65 4f 66 4f 6c 64 53 69 64 73 20 3d 20 25 78 } //01 00 
		$a_01_2 = {83 e8 fa 40 40 40 40 40 40 } //02 00 
		$a_01_3 = {8b 0c 19 68 44 64 6b 20 57 6a 01 } //03 00 
		$a_03_4 = {8b 4d 20 b8 14 80 7b 2a 3b c8 0f 87 90 01 02 00 00 0f 84 90 00 } //04 00 
		$a_01_5 = {25 77 73 0a 00 55 8b ec 83 ec 34 53 56 8b 75 24 57 33 ff 89 7d fc 89 3e 89 7e 04 } //00 00 
	condition:
		any of ($a_*)
 
}