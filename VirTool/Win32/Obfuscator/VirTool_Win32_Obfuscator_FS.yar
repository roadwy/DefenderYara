
rule VirTool_Win32_Obfuscator_FS{
	meta:
		description = "VirTool:Win32/Obfuscator.FS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_07_0 = {83 f9 00 75 90 01 01 90 03 01 06 58 8b 04 24 83 c4 04 89 c2 ff e2 c3 90 00 } //1
		$a_07_1 = {83 f9 00 75 90 01 01 58 ff e0 c3 90 00 } //1
	condition:
		((#a_07_0  & 1)*1+(#a_07_1  & 1)*1) >=1
 
}