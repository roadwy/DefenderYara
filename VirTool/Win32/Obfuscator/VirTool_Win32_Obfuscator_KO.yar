
rule VirTool_Win32_Obfuscator_KO{
	meta:
		description = "VirTool:Win32/Obfuscator.KO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {3e 8b 49 30 3e 8b 41 0c } //1
		$a_01_1 = {89 48 01 c6 40 05 c3 } //1
		$a_01_2 = {0f b7 51 06 6b d2 28 8d 84 10 38 01 00 00 50 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}