
rule VirTool_Win64_Amseosz_A_MTB{
	meta:
		description = "VirTool:Win64/Amseosz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 8b c8 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 0f 57 c0 48 8d ?? ?? ?? ?? ?? 48 8b d8 48 8d ?? ?? ?? 33 c0 89 84 } //1
		$a_03_1 = {48 89 44 24 30 4c 8d ?? ?? ?? 48 8d ?? ?? ?? 41 b9 04 00 00 00 48 8d ?? ?? ?? 48 89 44 24 20 48 8b cf ff 15 } //1
		$a_03_2 = {41 b9 01 00 00 00 48 c7 44 24 20 00 00 00 00 4c 8d ?? ?? ?? 48 8b cf ff 15 } //1
		$a_03_3 = {48 8b 4a 08 48 89 bc 24 d0 00 00 00 ff 15 ?? ?? ?? ?? 33 d2 44 8b c0 8d ?? ?? ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}