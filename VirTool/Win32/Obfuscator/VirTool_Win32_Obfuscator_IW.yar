
rule VirTool_Win32_Obfuscator_IW{
	meta:
		description = "VirTool:Win32/Obfuscator.IW,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 69 72 74 c7 45 90 01 01 75 61 6c 50 c7 45 90 01 01 72 6f 74 65 c7 45 90 01 01 63 74 45 78 c6 45 90 01 01 00 c6 45 90 01 01 6b c6 45 90 01 01 00 c6 45 90 01 01 65 c6 45 90 01 01 00 c6 45 90 01 01 72 90 00 } //1
		$a_03_1 = {ff d1 c9 c3 ba 90 01 04 89 d1 31 d2 41 42 81 fa 90 01 04 75 f6 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}