
rule VirTool_Win32_Obfuscator_CAE{
	meta:
		description = "VirTool:Win32/Obfuscator.CAE,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 db 4b 75 fb } //1
		$a_01_1 = {66 0f 6e d2 31 d2 66 0f 7e d2 } //1
		$a_01_2 = {89 d2 90 89 f6 90 89 c9 90 4b 75 f4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}