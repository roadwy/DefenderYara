
rule VirTool_Win32_Sliver_B_MTB{
	meta:
		description = "VirTool:Win32/Sliver.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 20 89 04 24 c7 44 24 08 00 00 00 00 8b 44 24 1c 89 44 24 04 e8 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 89 04 24 c7 44 24 04 00 00 00 00 8b 44 24 1c 89 44 24 08 c7 44 24 0c 00 30 00 00 c7 44 24 10 04 00 00 00 e8 ?? ?? ?? ?? 8b 44 24 14 89 44 24 24 83 c4 18 c3 } //1
		$a_03_1 = {83 ec 20 8d ?? ?? ?? ?? ?? 84 00 8b 05 ?? ?? ?? ?? 8b 4c 24 24 8b 15 ?? ?? ?? ?? 89 04 24 c7 44 24 04 00 00 00 00 c7 44 24 08 00 00 00 00 89 54 24 0c 89 4c 24 10 c7 44 24 14 00 00 00 00 c7 44 24 18 00 00 00 00 e8 ?? ?? ?? ?? 8b 44 24 1c 85 c0 } //1
		$a_03_2 = {64 8b 0d 14 00 00 00 8b 89 00 00 00 00 3b 61 08 ?? ?? 83 ec 10 8b 4c 24 1c 8d ?? ?? 39 c1 ?? ?? 8b 44 24 18 0f b6 4c 01 ff 84 c9 ?? ?? 8b 0d ?? ?? ?? ?? 89 0c 24 8b 4c 24 14 89 4c 24 04 89 44 24 08 e8 ?? ?? ?? ?? 8b 44 24 0c 89 44 24 24 83 c4 10 c3 } //1
		$a_03_3 = {64 8b 05 14 00 00 00 8b 80 00 00 00 00 8b 40 18 8b 0d ?? ?? ?? ?? 8b 80 cc 01 00 00 89 0c 24 89 44 24 04 c7 44 24 08 ff ff ff ff e8 ?? ?? ?? ?? 8b 44 24 0c e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}