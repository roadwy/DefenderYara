
rule VirTool_Win32_Obfuscator_AG{
	meta:
		description = "VirTool:Win32/Obfuscator.AG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {fe ff ff ba 44 00 00 00 e8 90 01 02 ff ff 8d 85 90 01 01 ff ff ff ba 90 01 02 00 00 e8 90 01 02 ff ff 8d 85 90 01 02 ff ff 50 8d 85 90 01 02 ff ff 50 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 8d 90 01 02 fe ff ff 33 c0 e8 90 01 02 ff ff 8b 90 01 02 fe ff ff e8 90 01 02 ff ff 50 6a 00 e8 90 01 02 ff ff c7 85 18 ff ff ff 07 00 01 00 8d 85 18 ff ff ff 50 8b 85 90 01 02 ff ff 50 e8 90 01 02 ff ff 8d 45 90 01 01 50 6a 04 8d 45 90 01 01 50 8b 45 bc 83 c0 08 50 8b 85 90 01 02 ff ff 50 e8 90 01 02 ff ff 6a 40 68 00 30 00 00 8b 45 90 01 01 50 8b 45 90 01 01 8b 40 90 00 } //01 00 
		$a_02_1 = {34 50 8b 85 90 01 02 ff ff 50 e8 90 01 02 ff ff 8d 45 90 01 01 50 8b 45 90 01 01 50 8b 45 90 01 01 50 8b 45 90 01 01 8b 40 34 50 8b 85 90 01 02 ff ff 50 e8 90 01 02 ff ff 8d 45 90 01 01 50 6a 04 8b 45 90 01 01 83 c0 34 50 8b 45 bc 83 c0 08 50 8b 85 90 01 02 ff ff 50 e8 90 01 02 ff ff 8b 45 90 01 01 8b 40 34 8b 55 90 01 01 03 42 28 89 45 c8 8d 85 18 ff ff ff 50 8b 85 90 01 02 ff ff 50 e8 90 01 02 ff ff 8b 85 90 01 02 ff ff 50 e8 90 01 02 ff ff 33 c0 5a 59 59 64 89 10 68 90 01 02 00 10 8b 45 90 01 01 50 e8 90 01 02 ff ff 59 c3 90 00 } //01 00 
		$a_02_2 = {33 c0 55 68 90 01 02 00 10 64 ff 30 64 89 20 6a 0a 68 90 01 02 00 10 a1 90 01 02 00 10 50 e8 90 01 02 ff ff 8b d8 53 a1 90 01 02 00 10 50 e8 90 01 02 ff ff 8b f8 53 a1 90 01 02 00 10 50 e8 90 01 02 ff ff 8b 90 01 02 e8 90 01 02 ff ff 8b 90 01 01 85 90 01 01 74 26 8b d7 4a b8 90 01 02 00 10 e8 90 01 02 ff ff b8 90 01 02 00 10 e8 90 01 02 ff ff 8b cf 8b 90 01 01 e8 90 01 02 ff ff 90 01 01 e8 90 01 02 ff ff 8d 4d ec ba 90 01 02 00 10 a1 90 01 02 00 10 e8 90 01 02 ff ff 8b 55 ec b8 90 01 02 00 10 e8 90 01 02 ff ff b8 90 01 02 00 10 e8 90 01 02 ff ff e8 90 01 02 ff ff 33 c0 5a 59 59 64 89 10 68 90 01 02 00 10 8d 45 ec e8 90 01 02 ff ff c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}