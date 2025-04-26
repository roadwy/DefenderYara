
rule VirTool_Win32_Obfuscator_AEN{
	meta:
		description = "VirTool:Win32/Obfuscator.AEN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 45 f4 b5 fb 04 00 } //1
		$a_01_1 = {c7 45 f4 65 4f 4e 00 } //1
		$a_01_2 = {c7 45 dc e4 fd 52 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}