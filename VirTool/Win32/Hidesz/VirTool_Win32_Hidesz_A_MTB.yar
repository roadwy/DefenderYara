
rule VirTool_Win32_Hidesz_A_MTB{
	meta:
		description = "VirTool:Win32/Hidesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8b 18 8b 43 04 89 44 24 04 8b 03 89 04 24 e8 02 ?? ?? ?? 89 43 10 83 f8 ff 0f 84 87 08 00 00 89 44 } //1
		$a_03_1 = {8b 03 8b b0 fc 00 00 00 e8 7d ?? ?? ?? 05 ec 29 00 00 2d 94 2a 00 00 89 04 24 ff ?? 51 85 c0 74 a7 0f bf 48 0a 8b 40 0c 8d 95 } //1
		$a_03_2 = {8b 03 89 44 24 08 8b 45 d0 89 34 24 89 44 24 04 e8 61 ?? ?? ?? 85 c0 7e 4e 31 } //1
		$a_03_3 = {89 c7 89 44 24 04 89 34 24 ff ?? ?? 31 c0 51 51 89 44 24 08 89 74 24 04 8b 45 08 89 04 24 ff 93 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}