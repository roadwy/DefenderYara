
rule VirTool_Win32_Obfuscator_AOP{
	meta:
		description = "VirTool:Win32/Obfuscator.AOP,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 08 83 e9 53 8b 55 e8 03 55 a4 88 0a eb d9 c7 45 fc ee ff 00 00 ff 75 ec 8b 45 e8 89 45 cc ff 55 cc } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_AOP_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AOP,SIGNATURE_TYPE_PEHSTR_EXT,06 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b fb 8b cf 66 0f ef c0 8d b6 00 00 00 00 8d bf 00 00 00 00 b8 67 66 66 66 f7 e9 8b d9 c1 fb 1f c1 fa 02 2b d3 8d 04 92 03 c0 f7 d8 03 c1 0f b6 1c 30 b8 67 66 66 66 f7 ef 41 30 9c 3c } //01 00 
		$a_03_1 = {ff d0 6a 40 68 00 30 00 00 90 02 18 ff 54 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}