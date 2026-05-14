
rule VirTool_Win64_Gesenesz_A{
	meta:
		description = "VirTool:Win64/Gesenesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 ff c7 44 38 24 38 ?? ?? 48 85 f6 ?? ?? 48 85 ff ?? ?? 4d 8b c4 48 85 f6 ?? ?? 33 d2 49 8b c0 48 f7 f7 0f b6 44 14 48 41 30 04 28 49 ff c0 4c 3b c6 } //1
		$a_03_1 = {41 c1 e0 06 44 0b c2 41 83 eb 06 ?? ?? 48 3b ce ?? ?? 41 8b c0 c1 f8 10 88 04 29 48 ff c1 48 3b ce ?? ?? 41 8b c0 c1 f8 08 88 04 29 48 ff c1 48 3b ce } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}