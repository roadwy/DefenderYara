
rule VirTool_Win32_Obfuscator_QK{
	meta:
		description = "VirTool:Win32/Obfuscator.QK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 01 00 00 00 c3 8b 65 e8 } //1
		$a_03_1 = {6a 40 68 00 30 00 00 68 58 04 00 00 6a 00 ff 55 ?? 89 45 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}