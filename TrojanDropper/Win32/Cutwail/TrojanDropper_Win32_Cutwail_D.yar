
rule TrojanDropper_Win32_Cutwail_D{
	meta:
		description = "TrojanDropper:Win32/Cutwail.D,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {5f 57 b8 00 00 00 00 4f 8b 33 0f ce 8a ca d3 e6 c1 ee 1f 85 f6 74 06 } //2
		$a_01_1 = {25 00 00 ff ff 2d 00 00 01 00 66 81 38 4d 5a 75 f4 } //2
		$a_01_2 = {46 f3 a4 61 c9 c3 6a 00 6a 04 6a 00 } //2
		$a_01_3 = {64 a1 00 00 00 00 8b 40 04 25 00 00 ff ff 2d 00 00 01 00 66 81 38 4d 5a 75 f4 } //2
		$a_01_4 = {8b 75 08 8b c6 83 c0 3c 8b 00 03 c6 05 80 00 00 00 8b } //2
		$a_00_5 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 SetThreadContext
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_00_5  & 1)*1) >=7
 
}