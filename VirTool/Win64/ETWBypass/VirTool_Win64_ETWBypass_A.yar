
rule VirTool_Win64_ETWBypass_A{
	meta:
		description = "VirTool:Win64/ETWBypass.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b 7d e0 48 89 7d d8 ff ?? ?? ?? ?? ?? c6 45 6f c3 48 c7 45 d0 00 00 00 00 ?? ?? ?? ?? 48 89 5c 24 20 ?? ?? ?? ?? 41 b9 01 00 00 00 48 89 c1 48 89 fa ff ?? ?? ?? ?? ?? 89 45 68 85 c0 ?? ?? ?? ?? ?? ?? 48 c7 45 b8 00 00 00 00 48 89 5d e0 ?? ?? ?? ?? ?? ?? ?? 48 89 45 e8 ?? ?? ?? ?? 48 89 45 f0 ?? ?? ?? ?? ?? ?? ?? 48 89 45 f8 ?? ?? ?? ?? ?? ?? ?? 48 89 45 30 48 c7 45 38 03 00 00 00 48 c7 45 50 00 00 00 00 48 89 75 40 48 c7 45 48 02 00 00 00 ?? ?? ?? ?? e8 } //1
		$a_03_1 = {0f b6 45 00 88 45 d0 0f 28 45 e0 0f 28 4d f0 0f 29 4d c0 0f 29 45 b0 ?? ?? ?? ?? 31 c9 31 d2 ff } //1
		$a_03_2 = {48 bb 32 a2 df 2d 99 2b 00 00 48 3b c3 ?? ?? 48 83 65 10 00 ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 48 8b 45 10 48 89 45 f0 ff ?? ?? ?? ?? ?? 8b c0 48 31 45 f0 ff ?? ?? ?? ?? ?? 8b c0 ?? ?? ?? ?? 48 31 45 f0 ff ?? ?? ?? ?? ?? 8b 45 18 ?? ?? ?? ?? 48 c1 e0 20 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}