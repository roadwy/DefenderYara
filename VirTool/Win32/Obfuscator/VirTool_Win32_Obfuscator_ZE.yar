
rule VirTool_Win32_Obfuscator_ZE{
	meta:
		description = "VirTool:Win32/Obfuscator.ZE,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {b9 37 13 00 00 66 89 4d d0 } //1
		$a_03_1 = {73 40 00 72 0f 85 90 09 03 00 80 3d } //1
		$a_01_2 = {00 00 4d 00 79 00 20 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 } //1
		$a_01_3 = {5c 74 72 69 6f 72 61 33 5c } //1 \triora3\
		$a_01_4 = {64 73 66 6b 6a 64 68 66 75 73 64 79 66 69 75 6a 68 6b 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}