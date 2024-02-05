
rule VirTool_Win32_Obfuscator_GM{
	meta:
		description = "VirTool:Win32/Obfuscator.GM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 f6 83 c0 00 83 e8 00 32 c2 83 eb 00 83 c3 00 aa 83 fa 63 02 d1 8b d2 } //01 00 
		$a_01_1 = {0f b6 30 6b c9 21 33 ce ff c0 68 ff ff ff ff 01 54 a4 00 5a 0f 85 e6 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}