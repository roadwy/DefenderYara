
rule VirTool_Win64_Amsipatch_B_MTB{
	meta:
		description = "VirTool:Win64/Amsipatch.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {81 39 44 31 52 4b 75 3a } //1
		$a_02_1 = {c7 45 bf 00 00 00 00 48 83 c3 0a 48 89 44 24 20 41 b9 04 00 00 00 48 c7 45 b7 00 10 00 00 4c 8d ?? ?? 48 89 5d c7 48 8d ?? ?? 48 8b cf ff 15 } //1
		$a_02_2 = {48 c7 44 24 20 00 00 00 00 4c 8d ?? ?? 48 8b d3 48 8b cf ff 15 } //1
		$a_02_3 = {44 8b 4d bf 48 8d ?? ?? 4c 8d ?? ?? 48 89 44 24 20 48 8d ?? ?? 48 8b cf ff 15 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}