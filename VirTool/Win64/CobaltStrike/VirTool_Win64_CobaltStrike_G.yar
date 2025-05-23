
rule VirTool_Win64_CobaltStrike_G{
	meta:
		description = "VirTool:Win64/CobaltStrike.G,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 b9 04 00 00 00 48 63 f2 49 89 cc 89 d7 4c 89 c5 48 89 f2 41 b8 00 30 00 00 31 c9 ff 15 } //1
		$a_03_1 = {41 b8 20 00 00 00 ff 15 ?? ?? ?? ?? 4c 8d ?? ?? ?? ?? ?? 49 89 d9 31 d2 31 c9 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 ff 15 } //1
		$a_01_2 = {c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00 } //1
		$a_01_3 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4d 53 53 45 2d 25 64 2d 73 65 72 76 65 72 } //1 %c%c%c%c%c%c%c%c%cMSSE-%d-server
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}