
rule VirTool_Win64_Ghostrikesz_A_MTB{
	meta:
		description = "VirTool:Win64/Ghostrikesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {55 53 48 81 ec a8 00 00 00 [0-20] 48 89 45 18 8b 05 23 43 00 00 89 c2 ?? ?? ?? ?? 49 89 d0 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 [0-13] 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 48 89 c2 ?? ?? ?? ?? 48 89 c1 } //1
		$a_03_1 = {48 89 c3 48 ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? 49 89 c0 48 89 da ?? ?? ?? ?? ?? c6 45 af 01 c7 45 a8 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 8b 45 a8 83 f8 03 ?? ?? ?? ?? ?? ?? 48 89 c1 } //1
		$a_03_2 = {89 da 89 c1 ?? ?? ?? ?? ?? 48 89 85 80 05 00 00 [0-12] 89 c3 [0-12] 89 da 89 c1 ?? ?? ?? ?? ?? 48 89 85 78 05 00 00 [0-12] 89 c3 [0-12] 89 da 89 c1 ?? ?? ?? ?? ?? 48 89 85 70 05 00 00 } //1
		$a_03_3 = {48 89 c3 48 ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? 48 8b 45 18 49 89 d1 49 89 d8 48 89 ca 48 89 c1 ?? ?? ?? ?? ?? 84 c0 ?? ?? b8 01 00 00 00 ?? ?? b8 00 00 00 00 84 c0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}