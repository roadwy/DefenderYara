
rule VirTool_Win32_Obfuscator_AJM{
	meta:
		description = "VirTool:Win32/Obfuscator.AJM,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 6c 4f 73 65 20 4e 65 77 20 54 79 50 65 20 57 41 56 65 41 55 44 69 4f 00 } //1
		$a_01_1 = {6d 63 69 53 65 6e 64 53 74 72 69 6e 67 41 00 } //1
		$a_03_2 = {89 c3 ba 30 00 00 00 80 c3 02 81 f6 90 01 04 31 f7 b9 90 01 04 8a 06 00 d8 aa 83 c6 01 e2 f6 e8 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}