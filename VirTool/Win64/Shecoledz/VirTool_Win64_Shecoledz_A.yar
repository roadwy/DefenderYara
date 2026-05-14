
rule VirTool_Win64_Shecoledz_A{
	meta:
		description = "VirTool:Win64/Shecoledz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 ff c1 48 81 f9 00 00 20 00 ?? ?? ?? ?? ?? ?? 48 89 d3 80 3a 0f ?? ?? 80 7a 01 05 ?? ?? ?? 80 7a 02 c3 ?? ?? 48 89 d8 48 83 c4 10 5d c3 } //1
		$a_03_1 = {48 89 4c 24 38 48 89 44 24 40 48 8b [0-19] bf 2e 00 00 00 ?? ?? ?? ?? ?? 41 b8 01 00 00 00 4d 89 c1 66 ?? e8 ?? ?? ?? ?? 48 8b 44 24 58 48 8b 5c 24 60 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}