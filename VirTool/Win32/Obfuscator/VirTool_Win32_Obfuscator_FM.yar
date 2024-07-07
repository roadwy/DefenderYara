
rule VirTool_Win32_Obfuscator_FM{
	meta:
		description = "VirTool:Win32/Obfuscator.FM,SIGNATURE_TYPE_PEHSTR_EXT,06 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {3b df 74 3a c7 45 f8 90 01 04 81 45 f8 90 00 } //2
		$a_01_1 = {3b c7 59 74 02 ff d0 57 ff 15 } //1
		$a_01_2 = {2b 45 10 33 cf 2b f1 83 7d fc 00 77 c2 } //1
		$a_01_3 = {68 00 00 ff ff 56 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}