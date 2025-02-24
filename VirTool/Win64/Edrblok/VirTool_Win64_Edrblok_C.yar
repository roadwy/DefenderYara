
rule VirTool_Win64_Edrblok_C{
	meta:
		description = "VirTool:Win64/Edrblok.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {d1 57 8d c3 ?? ?? ?? ?? a7 05 ?? ?? ?? ?? 33 4c ?? ?? 90 90 4f 7f bc ee e6 0e 82 } //1
		$a_03_1 = {87 1e 8e d7 ?? ?? ?? ?? 44 86 ?? ?? ?? ?? a5 4e ?? ?? 94 37 d8 09 ec ef c9 71 } //1
		$a_03_2 = {3b 39 72 4a ?? ?? ?? ?? 9f 31 ?? ?? ?? ?? bc 44 ?? ?? 84 c3 ba 54 dc b3 b6 b4 } //1
		$a_01_3 = {b8 00 00 00 00 b9 41 00 00 00 48 89 d7 f3 48 ab c7 85 2c 03 00 00 04 01 00 00 66 0f ef c0 0f 11 45 b0 0f 11 45 c0 66 0f d6 45 d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}