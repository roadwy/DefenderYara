
rule VirTool_Win64_Shafodesz_A_MTB{
	meta:
		description = "VirTool:Win64/Shafodesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 b9 00 00 00 00 41 b8 bb 01 00 00 48 8d ?? ?? ?? ?? ?? 48 89 c1 48 8b 05 10 ea 00 00 ff ?? 48 8b 55 10 48 89 02 48 8b 45 10 48 8b 00 48 } //1
		$a_03_1 = {48 89 8d 00 08 00 00 48 89 95 08 08 00 00 48 8d ?? ?? ?? ?? ?? 48 89 85 e0 07 00 00 48 ?? ?? ?? 41 b8 00 08 00 00 ba 00 00 00 00 48 89 c1 e8 ?? ?? ?? ?? 48 8b 95 e0 07 00 00 48 ?? ?? ?? 48 } //1
		$a_03_2 = {48 8b 85 08 14 00 00 48 8d ?? ?? ?? ?? ?? 48 89 c1 e8 ?? ?? ?? ?? 85 c0 75 14 e8 ?? ?? ?? ?? 48 8b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}