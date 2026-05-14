
rule VirTool_Win64_Aethesz_A{
	meta:
		description = "VirTool:Win64/Aethesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 89 e1 e8 ?? ?? ?? ?? 89 c1 48 69 c9 ?? ?? ?? ?? 48 c1 e9 27 69 c9 d0 07 00 00 f7 d9 ?? ?? ?? 81 c2 d0 07 00 00 31 c9 ff ?? ?? ?? ?? ?? 48 8b 95 80 1c 00 00 48 85 d2 } //1
		$a_01_1 = {48 8b 85 80 1d 00 00 c6 00 02 48 c7 85 88 1d 00 00 01 00 00 00 48 8b 85 78 1d 00 00 48 ff c8 ba 01 00 00 00 48 83 f8 0f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}