
rule VirTool_Win64_Beondresz_A_MTB{
	meta:
		description = "VirTool:Win64/Beondresz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {55 53 48 81 ec b8 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 4d 50 48 89 55 58 ?? ?? ?? ?? 48 89 c1 [0-13] 49 89 d0 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 55 58 49 89 d0 } //1
		$a_03_1 = {55 56 53 48 89 e5 48 81 ec b0 00 00 00 48 89 4d 20 48 89 55 28 ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 49 89 c0 ?? ?? ?? ?? ?? ?? ?? 48 8b 4d 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 48 8b 45 28 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 48 8b 05 9b b0 0c 00 ?? ?? 48 89 45 f8 48 83 7d f8 00 } //1
		$a_03_2 = {55 53 48 81 ec 58 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 8d f0 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 20 41 b9 19 00 02 00 41 b8 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 c7 c1 02 00 00 80 ?? ?? ?? ?? ?? ?? ?? ?? ?? 85 c0 0f 94 c0 84 c0 } //1
		$a_03_3 = {41 b8 00 00 00 00 ba 01 00 00 00 b9 02 00 00 00 48 8b 05 1d ac 0c 00 ?? ?? 48 89 85 38 06 00 00 48 83 bd 38 06 00 00 ff 0f 94 c0 84 c0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}