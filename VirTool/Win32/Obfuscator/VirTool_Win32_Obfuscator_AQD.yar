
rule VirTool_Win32_Obfuscator_AQD{
	meta:
		description = "VirTool:Win32/Obfuscator.AQD,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 45 f8 7b 00 00 00 8b 45 f8 35 28 1e 00 00 89 45 f8 8b 4d 10 81 c1 f6 06 00 00 89 4d f8 eb 27 c7 45 fc 14 00 00 00 0f be 55 14 81 f2 27 1a 00 00 89 55 fc 81 7d 10 8b 00 00 00 7d 0a 0f be 45 14 23 45 fc 89 45 fc 8b 0d 90 01 04 81 c1 2c 01 00 00 89 0d 90 01 04 0f b6 55 14 52 6a 05 e8 a5 0a 00 00 90 00 } //01 00 
		$a_01_1 = {66 89 4d f8 83 7d 14 78 7e 0e 0f bf 55 f8 81 f2 1c 3a 00 00 66 89 55 f8 81 7d 14 ec 00 00 00 7c 0d 0f bf 45 f8 25 27 69 00 00 66 89 45 f8 ff 15 } //00 00 
		$a_00_2 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}