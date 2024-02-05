
rule VirTool_Win32_CeeInject_GF{
	meta:
		description = "VirTool:Win32/CeeInject.GF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 38 e9 75 0b ba ff ff 00 00 66 39 50 03 74 07 40 41 83 f9 1e 7c e9 80 38 e9 } //01 00 
		$a_01_1 = {c7 44 24 64 a9 dd e5 62 c7 44 24 68 86 00 c2 1b 8b 74 24 10 8d 74 b4 38 ff 36 57 e8 } //01 00 
		$a_01_2 = {c7 84 3d e0 fe ff ff 2e 64 6c 6c c6 84 3d e4 fe ff ff 00 e8 } //00 00 
		$a_00_3 = {78 67 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_GF_2{
	meta:
		description = "VirTool:Win32/CeeInject.GF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 85 c8 fd ff ff 8b 0d 90 01 03 00 51 ff 15 90 01 03 00 83 c4 04 8b 55 f4 90 00 } //01 00 
		$a_03_1 = {00 03 95 58 ff ff ff 88 0a 8b 85 bc fe ff ff 83 e0 d2 0f b6 4d f2 0f b7 95 40 ff ff ff 2b ca 0b c1 88 85 2f ff ff ff 0f b7 85 08 ff ff ff b9 26 00 00 00 90 09 05 00 8b 15 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_GF_3{
	meta:
		description = "VirTool:Win32/CeeInject.GF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c2 21 89 95 fc fe ff ff 6a 40 68 00 10 00 00 8b 85 00 ff ff ff 50 6a 00 ff 15 9c e0 40 00 a3 90 01 03 00 0f b7 8d 6c fd ff ff 83 c1 60 0f b6 95 f3 fe ff ff 33 ca 90 00 } //01 00 
		$a_03_1 = {c7 85 fc fe ff ff 57 00 00 00 8b 95 e8 fe ff ff 2b 95 48 fe ff ff 83 ea 26 66 89 95 34 fe ff ff a1 90 01 04 50 ff 15 90 00 } //01 00 
		$a_00_2 = {7e } //15 00 
	condition:
		any of ($a_*)
 
}