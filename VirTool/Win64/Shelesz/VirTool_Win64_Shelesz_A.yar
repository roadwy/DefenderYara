
rule VirTool_Win64_Shelesz_A{
	meta:
		description = "VirTool:Win64/Shelesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 45 e7 8b 55 e7 83 c2 7d 33 54 85 f3 48 63 45 e7 89 54 85 f3 8b 45 e7 03 c7 89 45 e7 8b 45 e7 3b c7 ?? ?? 44 8b 4d fb 44 8b 45 f3 ba } //1
		$a_01_1 = {48 63 45 e7 8b 55 e7 83 c2 7c 33 54 85 fb 48 63 45 e7 89 54 85 fb 8b 45 e7 03 c7 89 45 e7 8b 45 e7 3b c7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule VirTool_Win64_Shelesz_A_2{
	meta:
		description = "VirTool:Win64/Shelesz.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4d 88 48 8b 01 ff ?? ?? 48 8b 4c 24 70 ?? ?? ?? ?? 48 8b 01 ff ?? ?? 48 8b 45 80 b9 18 00 00 00 4c 8b 30 e8 ?? ?? ?? ?? 48 8b d8 48 85 c0 } //1
		$a_03_1 = {b8 01 00 00 00 ?? ?? ?? ?? ?? 33 d2 33 c9 ff ?? ?? ?? ?? ?? 85 c0 } //1
		$a_03_2 = {48 8b 56 20 48 8b 01 ff ?? ?? 48 8b 4d ?? 48 8b 01 ff ?? ?? 48 8b 4d b0 48 8b 01 ff ?? ?? 48 8b 4d b8 48 8b 01 ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule VirTool_Win64_Shelesz_A_3{
	meta:
		description = "VirTool:Win64/Shelesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 48 89 e5 48 81 ec e8 00 00 00 48 89 84 24 f8 00 00 00 48 89 9c 24 00 01 00 00 ?? ba 01 00 00 00 f0 0f c1 50 38 ff c2 85 d2 ?? ?? 48 83 c0 34 31 db 31 c9 e8 ?? ?? ?? ?? 48 8b } //1
		$a_01_1 = {55 48 89 e5 48 81 ec b8 00 00 00 66 44 0f d6 bc 24 b0 00 00 00 48 89 84 24 c8 00 00 00 48 89 9c 24 d0 00 00 00 c6 44 24 3f 00 44 0f 11 7c 24 40 84 00 48 83 c0 28 48 89 44 24 58 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}