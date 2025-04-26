
rule VirTool_Win32_Obfuscator_OG{
	meta:
		description = "VirTool:Win32/Obfuscator.OG,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b7 51 06 8b d9 81 c3 f8 00 00 00 c1 e0 1f d1 e0 f7 43 24 00 00 00 20 74 03 83 c8 01 f7 43 24 00 00 00 40 74 03 83 c8 02 f7 43 24 00 00 00 80 74 03 83 c8 04 f7 43 24 00 00 00 10 74 03 83 c8 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}