
rule VirTool_Win64_Vendetez_A{
	meta:
		description = "VirTool:Win64/Vendetez.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b c1 48 81 fa 00 10 00 00 ?? ?? 48 83 c2 27 48 8b 49 f8 48 2b c1 48 83 e8 08 48 83 f8 1f ?? ?? ?? ?? ?? ?? e8 } //1
		$a_03_1 = {48 83 ec 38 83 fa 01 ?? ?? 33 c0 ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 28 45 33 c9 33 d2 89 44 24 20 33 c9 ff } //1
		$a_03_2 = {4c 8b f0 48 3b c3 [0-13] 48 89 44 24 40 48 c7 44 24 48 66 00 00 00 ?? ?? ?? ?? ?? b1 01 e8 ?? ?? ?? ?? 45 8b c7 33 d2 b9 38 04 00 00 ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}