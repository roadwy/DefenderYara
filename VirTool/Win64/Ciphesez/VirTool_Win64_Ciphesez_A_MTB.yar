
rule VirTool_Win64_Ciphesez_A_MTB{
	meta:
		description = "VirTool:Win64/Ciphesez.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 89 74 24 10 89 44 24 0c c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 89 1c 24 e8 ?? ?? ?? ?? 83 ec 1c 85 } //1
		$a_03_1 = {8b 85 ec ef ff ff c7 44 24 10 00 00 00 00 89 74 24 04 89 1c 24 83 c0 01 89 44 24 0c 8b 85 e8 ef ff ff 89 44 24 08 e8 ?? ?? ?? ?? 83 ec 14 85 } //1
		$a_03_2 = {c7 44 24 04 00 10 00 00 89 44 24 08 89 1c 24 e8 ?? ?? ?? ?? 83 ec 0c 85 c0 0f 84 ?? ?? ?? ?? 8b 85 c0 ef ff ff 8b 95 c4 ef ff ff c1 e8 02 89 95 c8 ef ff ff 85 } //1
		$a_03_3 = {83 ec 1c 8b 44 24 20 c7 44 24 04 00 00 00 00 c7 04 24 ff 0f 1f 00 89 44 24 08 e8 ?? ?? ?? ?? 31 d2 83 ec 0c 85 } //1
		$a_03_4 = {c7 44 24 0c 00 80 00 00 c7 44 24 08 00 00 00 00 89 74 24 04 89 1c 24 e8 ?? ?? ?? ?? 83 ec 10 89 1c 24 e8 ?? ?? ?? ?? 50 c7 44 24 08 2e 00 00 00 c7 44 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}