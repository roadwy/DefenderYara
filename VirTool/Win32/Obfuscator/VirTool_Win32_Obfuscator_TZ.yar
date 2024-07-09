
rule VirTool_Win32_Obfuscator_TZ{
	meta:
		description = "VirTool:Win32/Obfuscator.TZ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 88 0b f6 ff ff 90 18 03 88 2b f9 ff ff } //1
		$a_01_1 = {b8 0b f6 fd 7f 8b 80 ed 0c 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}