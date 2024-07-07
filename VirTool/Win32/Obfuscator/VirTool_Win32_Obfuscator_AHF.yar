
rule VirTool_Win32_Obfuscator_AHF{
	meta:
		description = "VirTool:Win32/Obfuscator.AHF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {77 6b 66 6e 6b 77 65 64 6c 73 00 } //1
		$a_01_1 = {c6 45 ec 2a c6 45 f4 63 c7 45 e8 28 3a 00 00 c7 45 f0 31 62 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}