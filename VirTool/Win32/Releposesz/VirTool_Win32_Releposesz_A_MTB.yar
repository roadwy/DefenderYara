
rule VirTool_Win32_Releposesz_A_MTB{
	meta:
		description = "VirTool:Win32/Releposesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 40 08 b8 00 00 00 89 c3 c7 40 0c 00 00 00 ff c6 40 10 e0 8b 44 24 70 89 44 24 48 8b 03 83 f8 01 } //1
		$a_03_1 = {ba d0 20 2e d0 b9 ed b5 d3 22 48 89 c7 e8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 41 b9 40 00 00 00 4c ?? ?? ?? ?? 49 89 c4 48 89 44 24 50 48 ?? ?? ?? ?? 48 c7 c1 ff ff ff ff 48 c7 44 24 58 18 00 00 00 48 89 44 24 20 ff ?? 4c 89 e1 41 b8 18 00 00 00 48 8d } //1
		$a_03_2 = {89 6c 24 0c 89 44 24 10 8b 44 24 28 89 5c 24 08 89 74 24 04 89 04 24 ff 15 ?? ?? ?? ?? 83 ec 14 89 c3 85 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}