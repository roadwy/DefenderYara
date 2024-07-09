
rule VirTool_Win32_Obfuscator{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d c0 2b 4d c0 89 4d c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule VirTool_Win32_Obfuscator_2{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b7 c0 69 c0 01 01 00 00 50 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule VirTool_Win32_Obfuscator_3{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 31 8b d8 0f 31 2b c3 50 83 f8 01 74 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule VirTool_Win32_Obfuscator_4{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 68 3e 8b 00 83 f8 70 74 90 09 06 00 64 a1 30 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_Obfuscator_5{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {94 8b 52 0c 8a 14 1a 8a 1c } //1
		$a_01_1 = {75 23 8b 51 14 8b 41 10 8b fb 2b fe 0f 80 } //1
		$a_01_2 = {ff 74 27 2b fe 8d 95 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule VirTool_Win32_Obfuscator_6{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {85 c9 8b c1 74 03 8d 04 09 8b 7d fc 8d 04 41 81 } //1
		$a_01_1 = {8d 14 31 85 d2 74 02 33 f6 03 c1 8b 7d 0c 03 c8 } //1
		$a_01_2 = {d0 8b c2 81 ef d2 02 96 49 f7 d8 89 7d fc 74 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule VirTool_Win32_Obfuscator_7{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,64 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {b8 4d 5a 00 00 66 39 07 75 17 8b 77 3c 81 fe 00 04 00 00 89 75 f8 7f 09 81 3c 3e 50 45 00 00 } //1
		$a_01_1 = {6a 40 68 00 30 00 00 52 6a 00 ff d3 } //1
		$a_03_2 = {68 34 01 00 00 68 ?? ?? ?? 00 51 89 5d f4 ff d7 } //1
		$a_03_3 = {8d 46 01 83 f8 3e 88 9e ?? ?? ?? 00 7d 19 ba 3e 00 00 00 2b d0 52 8d 88 ?? ?? ?? 00 6a 01 51 e8 ?? ?? ?? ?? 83 c4 0c } //1
		$a_03_4 = {00 40 49 3b c6 7c f2 90 09 07 00 8a 11 88 90 90 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule VirTool_Win32_Obfuscator_8{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 0a 00 00 "
		
	strings :
		$a_01_0 = {89 e5 53 56 83 e4 f8 83 ec } //1
		$a_01_1 = {24 07 74 08 8a 44 24 } //1
		$a_01_2 = {0f 93 c3 29 f1 0f 93 c7 } //1
		$a_01_3 = {00 00 29 cf 19 d6 8b } //1
		$a_01_4 = {31 c9 83 c1 18 89 44 24 } //1
		$a_01_5 = {00 00 31 d0 31 ce 35 } //1
		$a_01_6 = {00 0f 92 c2 31 db 85 c9 } //1
		$a_00_7 = {53 00 6f 00 6c 00 64 00 69 00 65 00 72 00 73 00 20 00 2d 00 20 00 41 00 72 00 65 00 6e 00 61 00 } //-100 Soldiers - Arena
		$a_00_8 = {47 00 61 00 74 00 65 00 73 00 20 00 4f 00 66 00 20 00 48 00 65 00 6c 00 6c 00 } //-100 Gates Of Hell
		$a_00_9 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 42 00 61 00 74 00 74 00 6c 00 65 00 20 00 6f 00 66 00 20 00 45 00 6d 00 70 00 69 00 72 00 65 00 73 00 } //-100
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*-100+(#a_00_8  & 1)*-100+(#a_00_9  & 1)*-100) >=2
 
}