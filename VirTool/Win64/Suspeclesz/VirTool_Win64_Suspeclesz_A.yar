
rule VirTool_Win64_Suspeclesz_A{
	meta:
		description = "VirTool:Win64/Suspeclesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 54 24 20 31 c9 48 89 44 24 48 [0-13] 48 89 44 24 40 31 c0 c7 44 24 64 04 00 00 00 48 89 44 24 38 48 89 44 24 30 c7 44 24 28 04 00 00 08 } //1
		$a_03_1 = {8b 54 24 70 48 89 d9 48 89 6c 24 20 ?? ?? ?? ?? ?? ?? ?? ?? 41 b9 40 00 00 00 48 01 f2 ff ?? 44 8b 84 24 3c 01 00 00 [0-18] 49 83 c6 02 ?? ?? ?? ?? ?? 48 89 d9 31 d2 ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}