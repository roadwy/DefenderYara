
rule VirTool_Win64_Prebembesz_A_MTB{
	meta:
		description = "VirTool:Win64/Prebembesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {48 8b 85 f0 01 00 00 48 89 e9 48 8b 95 58 02 00 00 41 b9 30 00 00 00 49 89 c8 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 83 f8 30 ?? ?? 8b 45 28 3d 00 00 04 00 ?? ?? 8b 45 24 83 f8 02 ?? ?? 48 8b 45 18 48 39 85 48 02 00 00 } //1
		$a_03_1 = {c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 41 b8 49 01 00 00 ba 00 00 00 00 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 28 02 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? ?? ?? 48 89 c2 } //1
		$a_03_2 = {49 89 d1 41 b8 00 00 00 00 ba 00 00 00 00 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 20 02 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b b5 38 02 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? ?? ?? 48 89 c2 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c2 48 8b 8d 28 02 00 00 48 8b 85 20 02 00 00 48 c7 44 24 20 49 01 00 00 49 89 f1 49 89 c8 48 89 c1 } //1
		$a_03_3 = {48 89 c2 b9 00 02 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 f8 48 8b 45 f8 48 89 c1 [0-11] b9 0a 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 05 29 c5 00 00 83 f8 02 ?? ?? 48 8b 45 f8 48 89 c1 } //1
		$a_03_4 = {c7 44 24 28 00 00 00 00 c7 44 24 20 01 00 00 00 41 b9 00 00 00 00 41 b8 00 00 00 00 ba 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? b9 e8 03 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}