
rule VirTool_Win32_Obfuscator{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d c0 2b 4d c0 89 4d c0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_2{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b7 c0 69 c0 01 01 00 00 50 e8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_3{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f 31 8b d8 0f 31 2b c3 50 83 f8 01 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_4{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c0 68 3e 8b 00 83 f8 70 74 90 09 06 00 64 a1 30 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_5{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {94 8b 52 0c 8a 14 1a 8a 1c } //01 00 
		$a_01_1 = {75 23 8b 51 14 8b 41 10 8b fb 2b fe 0f 80 } //01 00 
		$a_01_2 = {ff 74 27 2b fe 8d 95 } //00 00 
		$a_00_3 = {78 47 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_6{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {85 c9 8b c1 74 03 8d 04 09 8b 7d fc 8d 04 41 81 } //01 00 
		$a_01_1 = {8d 14 31 85 d2 74 02 33 f6 03 c1 8b 7d 0c 03 c8 } //01 00 
		$a_01_2 = {d0 8b c2 81 ef d2 02 96 49 f7 d8 89 7d fc 74 02 } //00 00 
		$a_00_3 = {78 } //96 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_7{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,64 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 4d 5a 00 00 66 39 07 75 17 8b 77 3c 81 fe 00 04 00 00 89 75 f8 7f 09 81 3c 3e 50 45 00 00 } //01 00 
		$a_01_1 = {6a 40 68 00 30 00 00 52 6a 00 ff d3 } //01 00 
		$a_03_2 = {68 34 01 00 00 68 90 01 03 00 51 89 5d f4 ff d7 90 00 } //01 00 
		$a_03_3 = {8d 46 01 83 f8 3e 88 9e 90 01 03 00 7d 19 ba 3e 00 00 00 2b d0 52 8d 88 90 01 03 00 6a 01 51 e8 90 01 04 83 c4 0c 90 00 } //01 00 
		$a_03_4 = {00 40 49 3b c6 7c f2 90 09 07 00 8a 11 88 90 90 90 00 } //00 00 
		$a_00_5 = {78 dd 00 00 } //0a 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_8{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 e5 53 56 83 e4 f8 83 ec } //01 00 
		$a_01_1 = {24 07 74 08 8a 44 24 } //01 00 
		$a_01_2 = {0f 93 c3 29 f1 0f 93 c7 } //01 00 
		$a_01_3 = {00 00 29 cf 19 d6 8b } //01 00 
		$a_01_4 = {31 c9 83 c1 18 89 44 24 } //01 00 
		$a_01_5 = {00 00 31 d0 31 ce 35 } //01 00 
		$a_01_6 = {00 0f 92 c2 31 db 85 c9 } //9c ff 
		$a_00_7 = {53 00 6f 00 6c 00 64 00 69 00 65 00 72 00 73 00 20 00 2d 00 20 00 41 00 72 00 65 00 6e 00 61 00 } //9c ff 
		$a_00_8 = {47 00 61 00 74 00 65 00 73 00 20 00 4f 00 66 00 20 00 48 00 65 00 6c 00 6c 00 } //9c ff 
		$a_00_9 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 42 00 61 00 74 00 74 00 6c 00 65 00 20 00 6f 00 66 00 20 00 45 00 6d 00 70 00 69 00 72 00 65 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}