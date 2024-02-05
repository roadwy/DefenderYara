
rule VirTool_Win32_Obfuscator_SK{
	meta:
		description = "VirTool:Win32/Obfuscator.SK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec ff 15 90 01 04 8b 4d 08 89 01 8b 55 08 8b 02 69 c0 a4 03 00 00 8b 4d 0c 8b 11 8d 44 02 9c a3 90 01 04 5d c3 90 00 } //01 00 
		$a_03_1 = {eb 09 8b 55 90 01 01 83 c2 04 89 55 90 01 01 81 7d 90 01 03 00 00 0f 83 90 01 04 8b 45 90 01 01 25 ff 00 00 00 83 f8 01 75 90 01 01 6a 00 68 90 01 04 ff 15 90 01 04 89 45 90 01 01 83 7d 90 01 01 00 74 90 01 01 68 90 01 04 ff 15 90 01 04 89 45 90 01 01 83 7d 90 01 01 00 74 90 01 01 6a 00 6a 00 8b 4d 90 01 01 51 8b 55 90 01 01 52 ff 15 90 01 04 89 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}