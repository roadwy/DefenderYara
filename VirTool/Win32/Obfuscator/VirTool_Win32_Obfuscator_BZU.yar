
rule VirTool_Win32_Obfuscator_BZU{
	meta:
		description = "VirTool:Win32/Obfuscator.BZU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 94 50 8b 4d f8 51 e8 90 01 01 00 00 00 88 45 e0 8b 55 fc 03 15 90 01 04 8a 45 e0 88 02 8a 4d e0 90 00 } //01 00 
		$a_01_1 = {eb 09 8b 45 8c 83 c0 01 89 45 8c 8b 4d 8c 3b 4d fc 73 38 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 } //01 00 
		$a_03_2 = {8b 4d fc 83 e9 01 39 4d 8c 75 0d 53 ff 75 fc 6a 00 ff 15 90 01 04 c3 eb b7 90 00 } //01 00 
		$a_01_3 = {8a 08 88 4d fc 8b 55 fc 81 e2 ff 00 00 00 33 c0 a0 70 45 41 00 33 d0 88 55 fc 8a 45 fc } //01 00 
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}