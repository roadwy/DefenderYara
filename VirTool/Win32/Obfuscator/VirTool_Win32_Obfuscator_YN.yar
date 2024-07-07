
rule VirTool_Win32_Obfuscator_YN{
	meta:
		description = "VirTool:Win32/Obfuscator.YN,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 68 9c 04 00 00 6a 00 ff 90 03 01 01 15 55 90 00 } //2
		$a_03_1 = {12 11 00 00 89 90 09 02 00 81 90 17 03 01 01 01 c1 c2 c3 90 00 } //1
		$a_01_2 = {05 12 11 00 00 89 85 } //1
		$a_01_3 = {80 f0 fa 02 73 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}