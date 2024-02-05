
rule VirTool_Win32_Obfuscator_PK{
	meta:
		description = "VirTool:Win32/Obfuscator.PK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 4d f4 c7 45 fc 00 00 00 00 eb 09 8b 55 fc 83 c2 08 89 55 fc 81 7d fc 90 01 02 00 00 0f 83 90 00 } //01 00 
		$a_01_1 = {8b 4d f4 03 c8 89 4d f4 8b 55 f8 03 55 fc 8b 02 03 45 ec 8b 4d f8 03 4d fc 89 01 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_PK_2{
	meta:
		description = "VirTool:Win32/Obfuscator.PK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 ff 00 20 00 00 0f 82 90 16 c6 85 e5 fd ff ff 00 90 00 } //01 00 
		$a_03_1 = {8d 44 95 e4 90 02 10 8b 08 90 00 } //01 00 
		$a_01_2 = {ff 74 b5 e4 } //01 00 
		$a_03_3 = {39 08 0f 84 90 01 02 00 00 90 02 10 8b d8 8b 03 90 02 10 8a 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_PK_3{
	meta:
		description = "VirTool:Win32/Obfuscator.PK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 40 04 8b 10 8b 00 } //01 00 
		$a_01_1 = {8b 52 3c 8b 44 02 50 } //01 00 
		$a_03_2 = {03 c1 8b 0d 90 01 02 40 00 8b 49 08 ff 31 ff d0 90 00 } //01 00 
		$a_03_3 = {48 8a 0c 30 90 02 20 80 e9 90 01 01 d0 c9 88 0c 30 3b c3 0f 85 90 16 48 8a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}