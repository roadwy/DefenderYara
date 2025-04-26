
rule VirTool_Win32_Obfuscator_DF{
	meta:
		description = "VirTool:Win32/Obfuscator.DF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 8b 15 30 00 00 00 8b 52 0c 8b 52 0c 8b 12 8d 7d e7 8b 72 30 b9 0d 00 00 00 66 ad aa 66 0b c0 74 02 } //1
		$a_01_1 = {b9 04 00 00 00 0f 31 89 04 24 89 54 24 04 cc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}