
rule VirTool_Win64_Shelcorid_B{
	meta:
		description = "VirTool:Win64/Shelcorid.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6b 00 65 00 48 8b f1 4c 89 7d ?? b9 13 9c bf bd } //1
		$a_03_1 = {52 74 6c 41 c7 45 ?? 64 64 46 75 c7 45 ?? 6e 63 74 69 c7 45 ?? 6f 6e 54 61 66 c7 ?? ?? 62 6c e8 ?? ?? ?? ?? b9 b5 41 d9 5e 48 8b d8 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win64_Shelcorid_B_2{
	meta:
		description = "VirTool:Win64/Shelcorid.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_03_0 = {e8 00 00 00 00 58 [0-30] 50 e8 ?? 00 00 00 83 c4 14 } //5
		$a_01_1 = {b9 13 9c bf bd } //1
		$a_01_2 = {b9 b5 41 d9 5e } //1
		$a_01_3 = {b9 49 f7 02 78 } //1
		$a_01_4 = {b9 58 a4 53 e5 } //1
		$a_01_5 = {b9 10 e1 8a c3 } //1
		$a_01_6 = {b9 af b1 5c 94 } //1
		$a_01_7 = {b9 33 00 9e 95 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}
rule VirTool_Win64_Shelcorid_B_3{
	meta:
		description = "VirTool:Win64/Shelcorid.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_03_0 = {e8 00 00 00 00 59 [0-40] c7 44 24 ?? ?? 00 00 00 e8 ?? 00 00 00 48 89 f4 } //5
		$a_01_1 = {b9 13 9c bf bd } //1
		$a_01_2 = {b9 b5 41 d9 5e } //1
		$a_01_3 = {b9 49 f7 02 78 } //1
		$a_01_4 = {b9 58 a4 53 e5 } //1
		$a_01_5 = {b9 10 e1 8a c3 } //1
		$a_01_6 = {b9 af b1 5c 94 } //1
		$a_01_7 = {b9 33 00 9e 95 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}