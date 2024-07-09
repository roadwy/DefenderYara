
rule VirTool_Win64_EpreLoad_A{
	meta:
		description = "VirTool:Win64/EpreLoad.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {81 38 4c 8b d1 b8 48 0f 45 d5 ?? ?? ?? ?? ?? 81 3f 4c 8b d1 b8 } //1
		$a_03_1 = {48 8b d3 48 0f 45 d5 ?? ?? ?? ?? ?? 81 3e 4c 8b d1 b8 } //1
		$a_01_2 = {48 0f 45 dd 48 8b d3 48 8b 5c 24 30 48 8b 6c 24 38 48 8b 74 24 40 48 83 c4 20 5f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}