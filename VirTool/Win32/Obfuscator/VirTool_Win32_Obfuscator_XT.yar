
rule VirTool_Win32_Obfuscator_XT{
	meta:
		description = "VirTool:Win32/Obfuscator.XT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff d3 8b f8 81 c7 4e 05 00 00 eb 02 ff d3 ff d3 3b f8 } //01 00 
		$a_01_1 = {89 c3 6a 02 6a 5f 6a 00 ff d6 50 ff d3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_XT_2{
	meta:
		description = "VirTool:Win32/Obfuscator.XT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {d1 c0 50 8f 85 90 01 02 ff ff e2 ef 3b c3 59 8b 85 90 01 02 ff ff 05 90 01 04 05 90 01 04 50 50 8f 85 90 01 02 ff ff 5b ac 32 c3 aa f7 c1 01 00 00 00 74 0b 90 09 06 00 8b 85 90 01 02 ff ff 90 00 } //01 00 
		$a_03_1 = {85 c0 60 6a 01 e8 90 01 04 61 e2 ae 8b 85 90 01 02 ff ff 05 ca 01 00 00 50 e8 90 01 04 c9 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_XT_3{
	meta:
		description = "VirTool:Win32/Obfuscator.XT,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {e8 00 00 00 00 58 89 45 fc 33 90 03 01 01 db f6 c6 45 90 01 01 56 c6 45 90 01 01 25 90 03 01 01 43 46 8b 45 fc 03 90 03 01 01 c3 c6 8b d0 4a 8a 12 3a 55 90 1b 01 75 f0 8a 10 3a 55 90 1b 02 75 e9 40 89 45 90 00 } //01 00 
		$a_03_1 = {33 db c6 45 90 01 01 56 c6 45 90 01 01 25 33 c0 89 45 fc e8 00 00 00 00 58 89 45 fc 43 90 03 13 15 8b 45 fc 03 c3 8b d0 4a 8a 12 3a 55 90 1b 00 75 f0 8a 10 8b 55 fc 8b c2 03 c3 8b c8 49 8a 09 3a 4d 90 1b 00 75 ee 8a 08 90 00 } //01 00 
		$a_03_2 = {ff d6 ff d6 3b 45 90 01 01 72 f7 66 83 ff 3b 72 10 66 83 ef 3b eb 0a 8d 85 90 01 04 50 ff 55 90 01 01 66 3b bd 90 01 04 75 ed e8 00 00 00 00 58 89 45 90 01 01 c6 45 90 01 01 54 c6 45 90 01 01 5e 90 00 } //01 00 
		$a_03_3 = {ff d7 ff d7 3b 45 90 01 01 72 f7 66 83 7d 90 01 01 3b 72 11 66 83 6d 90 01 01 3b eb 0a 8d 85 90 01 02 ff ff 50 ff 55 90 01 01 66 8b 45 90 01 01 66 3b 85 90 01 02 ff ff 75 e9 e8 00 00 00 00 58 89 45 90 01 01 c6 45 90 01 01 54 c6 45 90 01 01 5e 90 00 } //01 00 
		$a_03_4 = {ff d7 ff d7 3b f0 77 f8 66 83 fb 3b 72 10 66 83 eb 3b eb 0a 8d 85 90 01 02 ff ff 50 ff 55 90 01 01 66 3b 9d 90 01 02 ff ff 75 ed e8 00 00 00 00 58 89 45 90 01 01 c6 45 90 01 01 54 c6 45 90 01 01 5e 90 00 } //01 00 
		$a_03_5 = {ff d7 8b d8 81 c3 c8 03 00 00 eb 02 ff d7 ff d7 3b d8 77 f8 33 d2 c6 45 90 01 01 5e c6 45 90 01 01 54 e8 00 00 00 00 58 89 45 f8 90 00 } //01 00 
		$a_03_6 = {88 14 19 ff 45 f0 48 75 d7 50 51 53 8b 45 f4 8b 4d f0 b3 90 01 01 30 18 40 fe cb 84 db 75 02 b3 90 01 01 e2 f3 5b 59 58 ff 75 08 ff 55 f4 90 00 } //01 00 
		$a_03_7 = {68 05 01 00 00 8d 85 90 01 01 fe ff ff 50 6a 00 ff d7 50 ff 55 90 02 20 c6 45 90 01 01 6d c6 45 90 01 01 90 03 01 01 70 78 c6 45 90 01 01 90 03 01 01 70 78 8a 85 90 01 01 fe ff ff 3a 45 cc 75 17 90 00 } //01 00 
		$a_03_8 = {64 8b 05 30 00 00 00 8b 40 0c 8b 40 0c 8b 00 8b 00 8b 40 18 89 45 90 01 01 c6 45 90 02 06 50 c6 45 90 01 01 47 33 c0 90 03 05 02 89 45 90 01 01 89 c6 8b 5d 90 1b 00 8b 43 3c 03 c3 8b 50 78 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}