
rule VirTool_Win64_Cookidumpesz_MTB{
	meta:
		description = "VirTool:Win64/Cookidumpesz!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 b9 18 00 00 00 ?? ?? ?? ?? ?? 48 8b da 48 8b f9 ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 8b d3 [0-14] 48 8b 54 24 30 48 85 d2 } //1
		$a_03_1 = {48 8b 54 24 38 [0-12] 41 b8 08 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b 4c 24 38 [0-10] 48 89 44 24 20 41 b9 08 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b d3 [0-10] 85 c0 [0-14] 48 8b 54 24 38 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}