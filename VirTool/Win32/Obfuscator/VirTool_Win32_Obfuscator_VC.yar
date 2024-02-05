
rule VirTool_Win32_Obfuscator_VC{
	meta:
		description = "VirTool:Win32/Obfuscator.VC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d8 9c 80 0c 24 01 9d 0f 82 90 16 46 9c 80 0c 24 01 9d 0f 82 90 16 8b 83 90 01 03 00 9c 80 0c 24 01 9d 0f 82 90 16 03 83 90 01 03 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_VC_2{
	meta:
		description = "VirTool:Win32/Obfuscator.VC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b7 44 78 fe 04 80 88 45 f7 90 02 20 eb 90 14 8d 45 f0 0f b6 55 f7 32 d3 b9 00 00 00 00 90 00 } //01 00 
		$a_01_1 = {8b 02 3d 92 00 00 c0 7f 2c 74 5c } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_VC_3{
	meta:
		description = "VirTool:Win32/Obfuscator.VC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff d0 4a 75 83 50 58 60 8b } //01 00 
		$a_01_1 = {fe c0 f6 d8 04 9d fe c0 d0 c8 fc 90 aa 49 0f } //01 00 
		$a_01_2 = {ac 8b d2 fc 09 c0 d0 c8 f6 d8 34 e1 fc d0 c0 fe c0 d0 c0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_VC_4{
	meta:
		description = "VirTool:Win32/Obfuscator.VC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 f7 57 06 f2 e9 } //01 00 
		$a_01_1 = {68 ce 8a 23 69 e9 } //01 00 
		$a_01_2 = {68 8f b0 e9 11 e9 } //01 00 
		$a_01_3 = {68 60 d8 0d da e9 } //01 00 
		$a_01_4 = {68 d6 25 22 cb e9 } //01 00 
		$a_01_5 = {81 f9 b1 6b 89 31 e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_VC_5{
	meta:
		description = "VirTool:Win32/Obfuscator.VC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0d 00 ff ff ff 40 8a 90 90 90 01 04 30 14 1e a1 90 01 04 46 3b f0 72 8b a1 90 01 04 6a 00 6a 00 6a 03 6a 00 6a 03 68 00 00 00 80 90 00 } //01 00 
		$a_02_1 = {8a 04 2a 33 d2 8a d3 03 d6 03 c2 25 ff 00 00 00 8b f0 8a 86 90 01 04 88 81 90 01 04 41 81 f9 00 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_VC_6{
	meta:
		description = "VirTool:Win32/Obfuscator.VC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {bb 00 00 00 00 b9 04 00 00 00 53 e2 fd 68 90 01 04 53 53 e8 90 01 04 a3 90 01 04 bb 00 00 00 00 53 53 53 53 68 90 01 04 53 53 e8 90 00 } //01 00 
		$a_02_1 = {56 6a 01 e8 90 01 04 83 3d 90 01 04 02 75 f0 eb 19 46 50 83 c0 78 48 b8 90 01 04 c7 00 00 00 00 00 58 e2 d3 e9 f7 d6 ff ff 59 5e a1 90 01 04 8a 1e 32 d8 88 1e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}