
rule VirTool_Win32_Obfuscator_APB{
	meta:
		description = "VirTool:Win32/Obfuscator.APB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 65 d4 ff 75 d8 ff 75 e8 68 01 00 00 00 68 00 00 00 00 ff 75 f4 ff 75 f8 ff 15 90 01 04 90 05 07 01 90 39 65 d4 74 0d 90 00 } //1
		$a_03_1 = {68 5a 00 00 00 68 41 00 00 00 e8 90 01 04 68 01 01 00 80 90 00 } //1
		$a_03_2 = {68 39 00 00 00 68 30 00 00 00 e8 90 01 04 68 01 01 00 80 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}