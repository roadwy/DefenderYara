
rule VirTool_Win32_Obfuscator_DZ{
	meta:
		description = "VirTool:Win32/Obfuscator.DZ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {e8 01 00 00 00 c3 31 ff 89 e5 83 ec ?? 8d [55 5d 4d] [0-1a] ff 15 ?? ?? ?? ?? 31 90 04 01 0[8 90 04 0] 1 03 c2 c3 c[0 04 01 0] 3 d7 df cf 81 ef ?[1 ff ?? ?] ? ?? ?? 7c 90 04 01 03 a0 2d e0 [0-0a] 6a 40 68 [68 ?? ??] ?? 00 6a 00 ff 15 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}