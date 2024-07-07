
rule VirTool_Win32_Obfuscator_HL{
	meta:
		description = "VirTool:Win32/Obfuscator.HL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f 01 e0 03 c0 } //1
		$a_03_1 = {ba 65 e7 f8 75 f2 90 09 02 00 81 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}