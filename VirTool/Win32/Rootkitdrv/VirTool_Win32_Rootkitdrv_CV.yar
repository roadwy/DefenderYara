
rule VirTool_Win32_Rootkitdrv_CV{
	meta:
		description = "VirTool:Win32/Rootkitdrv.CV,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {89 65 e8 0f 20 c0 25 ff ff fe ff 0f 22 c0 33 c0 8b 75 08 3b 06 73 } //03 00 
		$a_03_1 = {80 39 e8 75 90 01 01 8b 51 01 8d 54 11 05 81 3a 58 83 c0 03 74 90 01 01 81 3a 58 ff 30 60 74 90 00 } //02 00 
		$a_03_2 = {66 81 38 28 0a 0f 85 90 01 03 00 6a 13 59 33 c0 8d 7d 98 f3 ab 90 00 } //02 00 
		$a_03_3 = {66 8b 06 66 3d 41 00 72 90 01 01 66 3d 5a 00 77 90 01 01 83 c0 20 66 89 06 46 57 46 ff d3 90 00 } //01 00 
		$a_03_4 = {0f b7 00 3d 93 08 00 00 0f 84 90 01 02 00 00 3d 28 0a 00 00 74 90 01 01 3d ce 0e 00 00 0f 85 90 01 03 00 6a 27 bb 97 00 90 00 } //02 00 
		$a_03_5 = {8b 46 60 89 5e 18 89 5e 1c 80 38 0e 75 90 01 01 8b 50 0c c7 46 1c 4c 06 00 00 b9 dc 05 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}