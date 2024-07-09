
rule VirTool_Win32_Obfuscator_IF{
	meta:
		description = "VirTool:Win32/Obfuscator.IF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 ee 6a 04 68 90 09 10 00 81 34 ?? ?? ?? ?? ?? 83 c1 04 81 f9 } //1
		$a_03_1 = {8b 58 3c 66 8b 44 03 16 66 25 00 20 74 05 e8 ?? ?? ?? ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}