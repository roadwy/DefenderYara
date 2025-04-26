
rule VirTool_Win64_Cookidumpesz_B_MTB{
	meta:
		description = "VirTool:Win64/Cookidumpesz.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 8b f0 41 b9 18 00 00 00 ?? ?? ?? ?? ?? 48 8b da 48 8b f9 ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 8b d3 [0-14] 48 8b 54 24 30 48 85 d2 } //1
		$a_03_1 = {48 8b 54 24 70 [0-12] 49 8b fe 4c 39 74 24 70 ?? ?? 48 8b 1c fe 48 85 db [0-18] 45 8b c5 [0-13] 48 ff c7 48 3b 7c 24 70 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}