
rule VirTool_Win64_Bedropesz_A_MTB{
	meta:
		description = "VirTool:Win64/Bedropesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b 0d 30 43 0a 00 [0-21] 48 89 85 a8 05 00 00 48 83 bd a8 05 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 0d dc 42 0a 00 ?? ?? ?? ?? ?? 41 b8 06 00 00 00 ba 01 00 00 00 b9 02 00 00 00 48 8b 05 34 ac 0c 00 ?? ?? 48 89 85 a0 05 00 00 48 83 bd a0 05 00 00 ff } //1
		$a_03_1 = {48 8b 85 a0 05 00 00 48 89 c1 48 8b 05 d1 aa 0c 00 [0-14] 48 8b 0d 98 41 0a 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ba 00 04 00 00 49 89 d0 ba 00 00 00 00 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 8d a0 05 00 00 41 b9 00 00 00 00 41 b8 00 04 00 00 48 89 c2 48 8b 05 9d aa 0c 00 } //1
		$a_03_2 = {48 8b 0d 12 41 0a 00 ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? 48 89 c2 ?? ?? ?? ?? ?? 48 8b 15 07 41 0a 00 48 89 c1 [0-13] 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}