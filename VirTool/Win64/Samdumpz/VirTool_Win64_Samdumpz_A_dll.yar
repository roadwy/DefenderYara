
rule VirTool_Win64_Samdumpz_A_dll{
	meta:
		description = "VirTool:Win64/Samdumpz.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f 57 c0 0f 57 c9 4c 8d ?? ?? 48 8d ?? ?? 41 b8 ff 0f 0f 00 33 c9 89 7d ff c7 45 e7 30 00 00 00 f3 0f 7f 45 ef f3 0f 7f 4d 07 ff } //1
		$a_03_1 = {48 8b 4d 87 48 8d ?? ?? 4c 8d ?? ?? 48 89 44 24 28 48 8d ?? ?? 45 33 c0 c7 44 24 20 ff ff 00 00 ff ?? ?? 89 45 6f } //1
		$a_03_2 = {48 8b 4c 24 38 4c 8d ?? ?? ba 12 00 00 00 41 ff ?? 85 c0 0f 88 } //1
		$a_03_3 = {33 d2 4c 8b c6 8d 4a ?? ff 15 ?? ?? ?? ?? 4c 8b f8 48 85 c0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}