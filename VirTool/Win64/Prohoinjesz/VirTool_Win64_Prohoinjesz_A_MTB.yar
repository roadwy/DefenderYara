
rule VirTool_Win64_Prohoinjesz_A_MTB{
	meta:
		description = "VirTool:Win64/Prohoinjesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 85 44 06 00 00 48 63 d8 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 48 39 c3 ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 b8 70 00 00 00 ba 00 00 00 00 48 89 c1 ?? ?? ?? ?? ?? 8b 85 4c 06 00 00 41 89 c0 ba 00 00 00 00 b9 00 00 00 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 10 02 00 00 } //1
		$a_03_1 = {c7 85 40 02 00 00 70 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 48 ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 40 48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 04 00 08 00 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 41 b8 00 00 00 00 } //1
		$a_03_2 = {48 89 85 08 06 00 00 48 8b 85 08 06 00 00 48 89 c2 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 48 c7 85 d8 01 00 00 00 00 00 00 48 c7 85 d0 01 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b 95 08 06 00 00 48 8b 85 20 06 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 4c 24 20 41 b9 08 00 00 00 48 89 c1 } //1
		$a_03_3 = {48 89 85 10 02 00 00 ?? ?? ?? ?? ?? ?? ?? 49 89 c1 41 b8 00 00 00 00 ba 01 00 00 00 b9 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 9d 18 02 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 49 89 d8 ba 00 00 00 00 48 89 c1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}