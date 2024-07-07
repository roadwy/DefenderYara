
rule VirTool_Win32_Obfuscator_MP{
	meta:
		description = "VirTool:Win32/Obfuscator.MP,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {35 fc 89 00 00 03 } //1
		$a_01_1 = {6a 01 68 78 58 64 78 68 88 67 59 76 } //1
		$a_01_2 = {b9 bd 3a 00 00 66 } //1
		$a_01_3 = {8b 4d 08 89 01 e9 07 00 00 00 81 75 fc } //1
		$a_01_4 = {76 4c bf 4c 6c 4c ba 4c 44 4c b5 4c 77 4c b0 4c 5b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}