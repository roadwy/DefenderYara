
rule VirTool_Win32_Obfuscator_RQ{
	meta:
		description = "VirTool:Win32/Obfuscator.RQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 42 24 03 45 d4 8b 4d 90 01 01 66 8b 14 48 66 89 95 24 ff ff ff 90 02 81 8b 51 1c 03 55 d4 8b 85 24 ff ff ff 25 ff ff 00 00 8b 04 82 03 45 d4 eb 07 e9 90 00 } //01 00 
		$a_03_1 = {89 85 38 ff ff ff 8b 85 38 ff ff ff 89 85 34 ff ff ff c7 45 fc 00 00 00 00 8b 8d 34 ff ff ff e8 90 01 04 50 68 90 01 04 8d 8d 3c ff ff ff 51 e8 90 01 0d 8b 95 30 ff ff ff 89 95 2c ff ff ff c6 45 fc 01 8b 8d 2c ff ff ff e8 90 01 04 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}