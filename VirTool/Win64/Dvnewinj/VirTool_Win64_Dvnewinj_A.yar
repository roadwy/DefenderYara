
rule VirTool_Win64_Dvnewinj_A{
	meta:
		description = "VirTool:Win64/Dvnewinj.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 f6 33 d2 8b fe ?? ?? ?? ff ?? ?? ?? ?? ?? 48 8b d8 48 83 f8 ff ?? ?? 48 ?? ?? ?? c7 45 b0 38 02 00 00 48 8b c8 ff ?? ?? ?? ?? ?? 48 8b cb 85 c0 ?? ?? 48 ?? ?? ?? ff } //1
		$a_03_1 = {41 b9 08 00 00 00 ?? ?? ?? ?? ?? 48 ff c3 48 89 44 24 20 4c 8b c6 48 8b d3 48 ff c7 ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 48 83 7c 24 50 08 } //1
		$a_03_2 = {eb 37 49 8b 06 48 3b 06 ?? ?? 48 8b d3 ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 41 b9 08 00 00 00 ?? ?? ?? ?? ?? 4d 8b c4 48 89 44 24 20 48 8b d3 ?? ?? ?? ?? ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}