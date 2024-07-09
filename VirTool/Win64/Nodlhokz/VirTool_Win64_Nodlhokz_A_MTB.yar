
rule VirTool_Win64_Nodlhokz_A_MTB{
	meta:
		description = "VirTool:Win64/Nodlhokz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {48 8b 50 18 48 03 d2 49 8b 0c d1 48 89 48 10 49 8b 4c d1 08 48 89 48 18 } //1
		$a_02_1 = {41 b8 ef be ad de 48 8d ?? ?? ?? ?? ?? 33 c9 ff ?? 48 8d ?? ?? ?? ?? ?? e8 } //1
		$a_02_2 = {49 c1 e0 04 4c 03 ?? ?? ?? ?? ?? 4d 8b 08 4d 8b 40 08 48 ff } //1
		$a_00_3 = {4c 8b c6 48 8b d5 8b cb ff } //1
		$a_02_4 = {48 c1 e7 05 ff 15 ?? ?? ?? ?? 4c 8b ?? ?? ?? ?? ?? 4c 8b cf 48 8b c8 33 d2 ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}