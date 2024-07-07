
rule VirTool_Win32_Obfuscator_BZN{
	meta:
		description = "VirTool:Win32/Obfuscator.BZN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 83 c4 04 50 56 03 f0 4e 8a 0e 5e 58 4b c0 c1 02 80 c1 f9 8a d0 fe ca 80 e2 01 32 ca 80 f1 03 81 e1 ff 00 00 00 80 64 06 ff 00 } //1
		$a_03_1 = {77 b5 7f b3 7e b1 61 e9 90 01 04 81 90 01 05 ff d6 90 00 } //1
		$a_01_2 = {3d 00 00 09 00 0f 87 2f 00 00 00 ba 00 50 02 00 3b c2 0f } //1
		$a_01_3 = {81 c6 f4 da ff ff ff d6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}
rule VirTool_Win32_Obfuscator_BZN_2{
	meta:
		description = "VirTool:Win32/Obfuscator.BZN,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 00 2f 2f 2f 2f 05 04 00 00 00 c7 00 2f 2f 2f 2f 05 04 00 00 00 c7 00 77 73 65 63 05 04 00 00 00 c7 00 65 64 69 74 } //1
		$a_01_1 = {8a 06 5e 59 4a 04 f9 8a d9 fe cb d1 cb 81 e3 00 00 00 a0 d1 c3 32 c3 34 f6 88 44 0e ff 83 e9 01 83 f9 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule VirTool_Win32_Obfuscator_BZN_3{
	meta:
		description = "VirTool:Win32/Obfuscator.BZN,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 00 2f 73 79 73 05 04 00 00 00 c7 00 75 65 6d 34 81 28 01 00 00 01 05 04 00 00 00 c7 00 32 2f 77 73 05 04 00 00 00 c7 00 65 63 65 64 } //1
		$a_01_1 = {8a 0e 5e 58 4b c0 c1 02 80 c1 f9 8a d0 fe ca 80 e2 01 32 ca 80 f1 03 88 4c 06 ff 2d 01 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}