
rule VirTool_Win64_Elevatekatz_B{
	meta:
		description = "VirTool:Win64/Elevatekatz.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 89 5c 24 18 48 89 74 24 20 57 48 81 ec 00 05 00 00 48 8b ?? ?? ?? ?? ?? 48 33 c4 48 89 84 24 f0 04 00 00 41 8b d8 48 8b f2 48 8b f9 ff } //1
		$a_03_1 = {45 33 ed 41 b9 40 00 00 00 48 89 44 24 20 ?? ?? ?? ?? ?? 4c 89 6c 24 70 49 8b d6 49 8b cc ff } //1
		$a_03_2 = {48 8b d7 e8 ?? ?? ?? ?? 41 b9 01 00 00 00 4c 89 74 24 20 ?? ?? ?? ?? 48 8b d7 49 8b cc ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 48 8b d7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}