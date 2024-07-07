
rule VirTool_Win32_Obfuscator_HW{
	meta:
		description = "VirTool:Win32/Obfuscator.HW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 c9 8a 2f 32 2a 88 2f fe c1 42 80 f9 04 75 05 31 c9 83 ea 04 47 39 f8 75 e8 } //1
		$a_13_1 = {00 00 00 00 01 fa b8 90 01 04 01 f8 89 c7 89 44 24 04 be 90 01 04 01 c6 80 38 00 75 05 8a 0a 88 08 42 40 39 c6 75 f1 e8 04 00 00 00 90 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_13_1  & 1)*1) >=1
 
}