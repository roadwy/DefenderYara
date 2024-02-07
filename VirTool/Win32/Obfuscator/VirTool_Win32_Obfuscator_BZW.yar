
rule VirTool_Win32_Obfuscator_BZW{
	meta:
		description = "VirTool:Win32/Obfuscator.BZW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 8a 45 10 88 45 fc 8b 4d 08 03 4d 0c 8a 55 fc 88 11 8b e5 } //01 00 
		$a_01_1 = {8b 45 b0 25 ff 00 00 00 8b 4d c8 8d 54 08 7b 88 55 b0 8b 85 68 ff ff ff 83 c0 01 89 85 68 ff ff ff 83 bd 68 ff ff ff 04 75 0a } //01 00 
		$a_03_2 = {75 09 8b 45 94 83 e8 01 89 45 94 8d 4d 94 51 ff 15 90 01 04 8b 55 fc 52 8d 45 94 50 ff 15 90 01 04 eb ae ff d3 90 00 } //01 00 
		$a_01_3 = {eb 09 8b 45 90 83 c0 01 89 45 90 8b 4d fc 03 4d fc 39 4d 90 73 3e } //01 00 
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}