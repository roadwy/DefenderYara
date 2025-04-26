
rule VirTool_Win32_Obfuscator_UO{
	meta:
		description = "VirTool:Win32/Obfuscator.UO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {c3 de c0 de c0 c3 } //1
		$a_01_1 = {8b 0e 89 0f 83 eb 04 83 c7 04 83 c6 04 85 db 75 ef } //1
		$a_01_2 = {31 c3 66 01 c3 c1 c3 07 e2 f1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}