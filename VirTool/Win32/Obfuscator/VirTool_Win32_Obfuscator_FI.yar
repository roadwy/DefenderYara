
rule VirTool_Win32_Obfuscator_FI{
	meta:
		description = "VirTool:Win32/Obfuscator.FI,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {58 2b 45 0c 03 45 d8 83 c0 0c ff e0 } //1
		$a_01_1 = {89 44 24 34 33 c0 ff 65 } //1
		$a_01_2 = {8b 75 18 8b 5d 14 ff 65 f0 } //1
		$a_01_3 = {b8 39 01 00 c0 eb 3f } //4
		$a_01_4 = {0f be 4d ff 33 c8 88 4d ff 8b 55 0c 8a 45 ff 88 02 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4) >=9
 
}