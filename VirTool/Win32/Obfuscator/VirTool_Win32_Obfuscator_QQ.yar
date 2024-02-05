
rule VirTool_Win32_Obfuscator_QQ{
	meta:
		description = "VirTool:Win32/Obfuscator.QQ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {55 8b ec 81 c4 5c ff ff ff 64 8b 3d 30 00 00 00 90 04 01 0b 03 0f 2b 3b 6b 83 8b b8 b9 ba be 90 02 04 90 04 01 0b 03 0f 2b 3b 6b 83 8b b8 b9 ba be 90 02 04 90 04 01 0b 03 0f 2b 3b 6b 83 8b b8 b9 ba be 90 02 04 90 04 01 0b 03 0f 2b 3b 6b 83 8b b8 b9 ba be 90 02 04 90 04 01 0b 03 0f 2b 3b 6b 83 8b b8 b9 ba be 90 00 } //01 00 
		$a_03_1 = {89 bd 5c ff ff ff 8b 5d e4 83 eb 90 01 01 c7 07 90 01 04 03 fb c7 07 90 01 04 03 fb c7 07 90 01 04 03 fb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}