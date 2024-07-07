
rule VirTool_Win32_Obfuscator_OS{
	meta:
		description = "VirTool:Win32/Obfuscator.OS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {bb 00 00 00 76 b8 01 00 00 00 e9 90 01 01 00 00 00 81 c3 00 10 00 00 8d 44 24 90 01 01 c7 00 6b 63 75 66 c7 40 04 70 73 61 6b c7 40 08 6b 73 72 65 c7 40 0c 79 00 00 00 90 00 } //1
		$a_03_1 = {81 7b 3c 00 10 00 00 77 90 01 01 03 5b 3c 8b 43 08 35 90 01 04 3d 90 01 04 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}