
rule VirTool_Win32_Obfuscator_AFC{
	meta:
		description = "VirTool:Win32/Obfuscator.AFC,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b d2 ba 00 ?? 40 00 92 e8 ?? ?? ?? ?? 68 ?? 10 40 00 5a ff e2 c3 } //1
		$a_01_1 = {6f 77 65 72 65 64 20 62 79 20 09 20 28 63 29 } //1
		$a_01_2 = {00 70 72 74 6b 2e 70 64 62 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}