
rule VirTool_Win32_Obfuscator_FN{
	meta:
		description = "VirTool:Win32/Obfuscator.FN,SIGNATURE_TYPE_PEHSTR_EXT,63 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {81 04 39 01 00 00 00 81 3c 39 ff ff ff ff 0f 85 ec ff ff ff 81 c1 04 00 00 00 81 f9 10 00 00 00 0f 85 da ff ff ff } //6
		$a_03_1 = {39 00 00 00 fa 0f 85 (ec|f0) ff ff ff 81 c1 04 00 00 00 81 f9 10 00 00 00 0f 85 90 03 01 01 da de ff ff ff } //6
		$a_03_2 = {ff f5 89 e5 81 ec ?? 00 00 00 ff f6 [0-20] e8 00 00 00 00 58 81 e8 ?? ?? 40 00 } //2
		$a_01_3 = {81 7f 0c ff ff ff ff 0f 85 } //1
		$a_01_4 = {47 80 34 31 } //1
		$a_01_5 = {89 ad fc ff ff ff 80 34 31 } //1
		$a_01_6 = {be 00 f0 7e 00 } //1
		$a_01_7 = {81 f9 c0 03 00 00 0f 85 } //1
	condition:
		((#a_01_0  & 1)*6+(#a_03_1  & 1)*6+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}