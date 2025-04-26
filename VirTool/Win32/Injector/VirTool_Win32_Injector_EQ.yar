
rule VirTool_Win32_Injector_EQ{
	meta:
		description = "VirTool:Win32/Injector.EQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_03_0 = {68 5a e4 3e c0 e8 ?? ?? ?? ?? (ff d0|e9) } //1
		$a_03_1 = {68 5a e4 3e c0 (e9|60 e9) } //1
		$a_03_2 = {68 0a ed dc e7 e8 ?? ?? ?? ?? (ff d0|e9) } //1
		$a_01_3 = {68 0a ed dc e7 e9 } //1
		$a_03_4 = {32 04 13 aa 42 (e9|3b 55 0c) } //1
		$a_03_5 = {32 04 13 e9 ?? ?? (00 00|ff ff) } //1
		$a_01_6 = {32 04 13 aa e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=3
 
}