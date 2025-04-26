
rule VirTool_Win32_Obfuscator_VB{
	meta:
		description = "VirTool:Win32/Obfuscator.VB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b c2 8a 14 08 30 91 ?? ?? ?? ?? 41 83 f9 0c 7e cb 53 } //1
		$a_03_1 = {f7 e6 2b f2 d1 ee 03 f2 c1 ee 04 8d 04 f5 00 00 00 00 2b c6 03 c0 03 c0 ba ?? ?? ?? ?? 2b d0 8a 04 0a 30 81 } //1
		$a_01_2 = {41 83 f9 12 7e cb b8 03 00 00 00 2d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}