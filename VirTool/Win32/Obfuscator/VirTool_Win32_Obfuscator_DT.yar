
rule VirTool_Win32_Obfuscator_DT{
	meta:
		description = "VirTool:Win32/Obfuscator.DT,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 06 00 07 00 00 "
		
	strings :
		$a_03_0 = {72 6f 74 65 [0-04] e8 } //1
		$a_01_1 = {81 f9 33 32 04 00 e8 } //1
		$a_01_2 = {81 fa 22 01 00 00 e8 } //1
		$a_01_3 = {83 c4 04 f3 a6 e8 } //1
		$a_01_4 = {83 c4 04 30 0f e8 } //2
		$a_01_5 = {8d 80 22 6c 00 00 e8 } //1
		$a_01_6 = {8d 88 00 60 00 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}