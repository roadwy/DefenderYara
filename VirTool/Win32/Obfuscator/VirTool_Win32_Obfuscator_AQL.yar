
rule VirTool_Win32_Obfuscator_AQL{
	meta:
		description = "VirTool:Win32/Obfuscator.AQL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {14 8a 04 02 90 13 30 01 90 13 41 } //2
		$a_01_1 = {51 89 d2 59 49 75 f9 } //1
		$a_01_2 = {52 5a 89 c9 48 75 f9 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}