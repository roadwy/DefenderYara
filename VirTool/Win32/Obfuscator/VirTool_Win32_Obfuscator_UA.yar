
rule VirTool_Win32_Obfuscator_UA{
	meta:
		description = "VirTool:Win32/Obfuscator.UA,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 8b cc 8b 44 24 04 68 90 01 01 7b 07 00 90 01 01 68 00 00 02 00 51 ff 15 90 01 04 8b c8 ba 90 01 04 c1 e9 1c 03 14 24 c1 e0 04 03 c2 8d 4c 0c 90 01 01 89 01 51 68 00 00 02 00 51 ff 15 90 01 04 83 c4 90 01 01 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}