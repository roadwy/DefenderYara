
rule VirTool_Win32_Obfuscator_ZL{
	meta:
		description = "VirTool:Win32/Obfuscator.ZL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 0f 00 00 "
		
	strings :
		$a_01_0 = {66 3d dd 07 74 06 66 3d de 07 75 } //1
		$a_03_1 = {04 30 32 c2 34 79 88 83 ?? ?? ?? ?? 33 d2 8b c3 b9 03 00 00 00 f7 f1 85 d2 74 } //1
		$a_01_2 = {8b c8 c1 e9 10 c1 e1 08 c1 e9 10 32 d1 } //1
		$a_01_3 = {8b c2 c1 e8 10 c1 e0 08 c1 e8 10 32 d8 } //1
		$a_01_4 = {8b c2 c1 e8 10 c1 e0 08 c1 e8 10 32 c8 } //1
		$a_03_5 = {8b c2 c1 e8 10 c1 e0 08 [0-12] c1 e8 10 32 d0 } //1
		$a_01_6 = {8b d6 c1 ea 10 c1 e2 08 c1 ea 10 32 d3 } //1
		$a_01_7 = {8b d6 c1 ea 10 c1 e2 08 c1 ea 10 32 d1 } //1
		$a_03_8 = {b9 89 d7 00 00 be [0-06] f3 a5 66 a5 [0-03] a4 } //1
		$a_03_9 = {b9 89 8f 00 00 be [0-06] f3 a5 66 a5 [0-03] a4 } //1
		$a_03_10 = {b9 89 53 00 00 be [0-06] f3 a5 66 a5 [0-03] a4 } //1
		$a_03_11 = {b9 09 56 00 00 be [0-06] f3 a5 66 a5 [0-03] a4 } //1
		$a_03_12 = {b9 89 10 00 00 be [0-06] f3 a5 66 a5 [0-03] a4 } //1
		$a_03_13 = {b9 89 d4 00 00 be [0-06] f3 a5 66 a5 [0-03] a4 } //1
		$a_01_14 = {6a 08 68 45 01 00 00 68 c9 01 00 00 6a 07 68 f4 01 00 00 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_03_8  & 1)*1+(#a_03_9  & 1)*1+(#a_03_10  & 1)*1+(#a_03_11  & 1)*1+(#a_03_12  & 1)*1+(#a_03_13  & 1)*1+(#a_01_14  & 1)*1) >=2
 
}