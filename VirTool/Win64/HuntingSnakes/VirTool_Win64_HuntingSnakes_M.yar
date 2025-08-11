
rule VirTool_Win64_HuntingSnakes_M{
	meta:
		description = "VirTool:Win64/HuntingSnakes.M,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 48 8b 85 ?? ?? ?? ?? 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0 48 89 85 } //1
		$a_03_1 = {8b 45 fc 48 98 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 45 28 48 01 d0 8b 00 48 63 d0 48 8b 45 30 48 01 d0 0f b6 00 88 45 fb } //1
		$a_03_2 = {48 c7 44 24 20 ?? ?? ?? ?? 4d 89 c1 49 89 c8 48 89 c1 41 ff d2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}