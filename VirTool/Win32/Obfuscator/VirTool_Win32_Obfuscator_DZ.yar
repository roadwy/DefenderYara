
rule VirTool_Win32_Obfuscator_DZ{
	meta:
		description = "VirTool:Win32/Obfuscator.DZ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {e8 01 00 00 00 c3 31 ff 89 e5 83 ec 90 01 01 8d 90 04 01 03 55 5d 4d 90 02 1a ff 15 90 01 04 31 90 04 01 03 d2 db c9 88 90 04 01 03 c2 c3 c1 89 ec 01 90 04 01 03 d7 df cf 81 ef 90 01 01 00 00 00 81 ff 90 01 04 7c 90 04 01 03 a0 2d e0 90 02 0a 6a 40 68 00 30 00 00 68 90 01 03 00 6a 00 ff 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}