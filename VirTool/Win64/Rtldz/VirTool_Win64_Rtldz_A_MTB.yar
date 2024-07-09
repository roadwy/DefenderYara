
rule VirTool_Win64_Rtldz_A_MTB{
	meta:
		description = "VirTool:Win64/Rtldz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {41 8b d4 41 8b ce e8 ?? ?? ?? ?? 48 8b f0 48 85 c0 0f 84 } //1
		$a_03_1 = {48 03 4b 08 48 8d ?? ?? 41 b8 20 00 00 00 e8 ?? ?? ?? ?? 83 43 10 20 } //1
		$a_01_2 = {48 8b 01 ff c7 48 8b c8 48 85 c0 75 } //1
		$a_03_3 = {48 8b 45 80 48 8d ?? ?? ?? 48 89 44 24 68 48 8d ?? ?? 48 89 44 24 78 48 89 74 24 60 44 89 6c 24 70 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}