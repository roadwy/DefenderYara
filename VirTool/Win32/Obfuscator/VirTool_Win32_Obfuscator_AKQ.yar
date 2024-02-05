
rule VirTool_Win32_Obfuscator_AKQ{
	meta:
		description = "VirTool:Win32/Obfuscator.AKQ,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 8d 50 ec ff ff 8a 55 fe 88 94 0d 58 ec ff ff 8b 85 50 ec ff ff 83 c0 01 89 85 50 ec ff ff 8b 8d 50 ec ff ff 3b 8d a0 eb ff ff 0f 85 90 01 02 ff ff 8d 95 74 ec ff ff ff d2 90 00 } //01 00 
		$a_01_1 = {c6 07 50 c6 47 01 24 c6 47 02 78 e8 00 00 00 00 58 89 45 fc 33 db e9 } //01 00 
		$a_03_2 = {8a 10 3a 57 01 0f 85 90 01 02 ff ff 40 8a 00 3a 47 02 0f 85 90 01 02 ff ff e9 90 00 } //01 00 
		$a_01_3 = {c6 07 50 c6 47 01 24 c6 47 02 78 e8 00 00 00 00 58 89 45 fc 33 c0 40 8b 0e 03 c8 } //01 00 
		$a_03_4 = {8a 1a 3a 5f 01 75 90 01 01 42 8a 12 3a 57 02 75 90 01 01 89 4d 90 01 01 03 06 90 00 } //01 00 
		$a_01_5 = {46 75 63 6b 69 6e 67 20 4e 4f 44 33 32 0a 00 } //00 00 
	condition:
		any of ($a_*)
 
}