
rule VirTool_Win32_Obfuscator_ZC{
	meta:
		description = "VirTool:Win32/Obfuscator.ZC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 8b 04 46 66 89 04 4a eb d5 c7 45 f4 00 00 00 00 eb 09 8b 4d f4 83 c1 01 89 4d f4 8b 55 f4 3b 55 14 73 41 8b 45 f4 8b 4d f8 8b 55 08 8b 04 81 33 02 } //01 00 
		$a_01_1 = {8b 7e 3c 68 4a 0d ce 09 e8 cf ff ff ff 85 c0 59 74 0f 6a 04 68 00 30 00 00 ff 74 37 50 6a 00 ff d0 } //00 00 
	condition:
		any of ($a_*)
 
}