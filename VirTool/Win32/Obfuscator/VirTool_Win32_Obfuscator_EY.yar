
rule VirTool_Win32_Obfuscator_EY{
	meta:
		description = "VirTool:Win32/Obfuscator.EY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b7 cf 0f a4 f7 64 0f a5 f7 47 11 e9 b9 a4 d7 3e 09 3a c6 f2 d1 d1 0f b7 fd 8b cd c7 c1 04 b7 9e e9 0f be c6 8b cd 0f a4 f7 b4 f7 c3 44 f7 de 29 38 f0 0f c1 c8 f2 f7 c3 84 37 1e 69 8a c6 47 47 eb 01 } //00 00 
	condition:
		any of ($a_*)
 
}