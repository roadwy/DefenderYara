
rule VirTool_Win64_Emoresz_A{
	meta:
		description = "VirTool:Win64/Emoresz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 31 c0 ff ?? 48 89 c6 48 b8 00 00 00 00 00 00 00 80 ?? ?? ?? ?? ?? 80 7f 01 8b ?? ?? 80 7f 02 d1 ?? ?? 80 7f 03 b8 } //1
		$a_03_1 = {48 8b 17 48 8b 47 08 48 89 d1 48 f7 d9 ?? ?? ?? ?? ?? ?? 48 c7 85 e8 01 00 00 00 00 00 00 4c 8b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}