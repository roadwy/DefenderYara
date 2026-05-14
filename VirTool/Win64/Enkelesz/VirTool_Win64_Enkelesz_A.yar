
rule VirTool_Win64_Enkelesz_A{
	meta:
		description = "VirTool:Win64/Enkelesz.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b da 48 8b f9 39 35 [0-13] e8 [0-11] 4c 8b c3 48 8b d7 e8 ?? ?? ?? ?? 48 8b 8f 18 29 19 00 ff ?? ?? ?? ?? ?? 39 35 } //1
		$a_03_1 = {48 83 ec 60 4c 8b b2 b8 00 00 00 4c 8b 69 40 8b 0d ?? ?? ?? ?? 48 8b 72 18 45 8b 66 10 41 8b 6e 08 45 33 ff 48 8b fa 41 3b cf 41 8b df } //1
		$a_03_2 = {48 8b da 48 8b f9 [0-12] 41 b8 68 00 00 00 e8 ?? ?? ?? ?? 33 ed 39 2d ?? ?? ?? ?? 48 89 6c 24 20 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}