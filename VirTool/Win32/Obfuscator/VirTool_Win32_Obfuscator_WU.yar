
rule VirTool_Win32_Obfuscator_WU{
	meta:
		description = "VirTool:Win32/Obfuscator.WU,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 75 18 8b 86 2c 11 00 00 0b 86 38 11 00 00 } //01 00 
		$a_03_1 = {39 9e 10 11 00 00 75 11 ff b6 08 11 00 00 57 ff 75 18 e8 90 01 02 ff ff 90 00 } //01 00 
		$a_03_2 = {8b 48 24 03 0d 90 01 04 89 4d c0 c7 45 cc 00 00 00 00 56 8b 7d cc c1 e7 02 03 7d d8 8b 3f 03 3d 90 01 04 8b 4d c4 f3 a6 74 07 5e 83 45 cc 01 eb e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_WU_2{
	meta:
		description = "VirTool:Win32/Obfuscator.WU,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {60 8b 45 08 25 00 ff ff ff 05 00 01 00 00 2d 00 01 00 00 66 81 38 4d 5a 75 f4 8b 48 3c 81 f9 00 10 00 00 77 e9 03 c8 81 39 50 45 00 00 75 df 89 45 fc 61 8b 45 fc 5f 5e 5b c9 c2 04 00 } //01 00 
		$a_03_1 = {8b 48 20 03 0d 90 01 04 89 4d cc 8b 48 24 03 0d 90 01 04 89 4d b0 c7 45 c0 00 00 00 00 56 8b 7d c0 c1 e7 02 03 7d cc 8b 3f 03 3d 90 01 04 8b 4d b8 f3 a6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}