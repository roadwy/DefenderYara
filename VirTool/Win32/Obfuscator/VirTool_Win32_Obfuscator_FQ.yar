
rule VirTool_Win32_Obfuscator_FQ{
	meta:
		description = "VirTool:Win32/Obfuscator.FQ,SIGNATURE_TYPE_PEHSTR_EXT,09 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 65 61 70 57 61 6c 6b 00 } //1
		$a_01_1 = {81 c0 01 00 00 00 ff c8 } //1
		$a_01_2 = {81 ef 01 00 00 00 47 } //1
		$a_01_3 = {81 ed 01 00 00 00 45 } //1
		$a_01_4 = {81 c2 01 00 00 00 ff ca } //1
		$a_03_5 = {81 f9 44 03 00 00 0f 85 90 09 33 00 90 02 30 80 34 31 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}