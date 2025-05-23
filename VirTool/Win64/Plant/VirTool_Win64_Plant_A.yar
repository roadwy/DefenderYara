
rule VirTool_Win64_Plant_A{
	meta:
		description = "VirTool:Win64/Plant.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {48 8b c8 e8 ?? ?? ?? ?? 48 89 44 24 50 ?? ?? ?? ?? ?? 48 89 44 24 20 ?? ?? ?? ?? ?? 41 b8 01 00 00 00 33 d2 33 c9 } //1
		$a_01_1 = {b8 13 00 00 00 66 89 44 24 24 c7 44 24 20 00 00 00 00 eb } //1
		$a_03_2 = {48 63 44 24 20 ?? ?? ?? ?? ?? ?? ?? ?? 24 00 01 00 00 48 8b 4c c4 60 ?? ?? ?? ?? ?? ?? 85 c0 75 } //1
		$a_01_3 = {48 89 44 24 20 44 8b 8c 24 88 00 00 00 4c 8b 84 24 10 01 00 00 48 8b 54 24 68 48 8b 8c 24 80 } //1
		$a_03_4 = {88 01 48 03 ce 03 c6 3d ?? ?? 00 00 7c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}