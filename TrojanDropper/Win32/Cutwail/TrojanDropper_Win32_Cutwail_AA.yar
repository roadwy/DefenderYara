
rule TrojanDropper_Win32_Cutwail_AA{
	meta:
		description = "TrojanDropper:Win32/Cutwail.AA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 0f 00 00 "
		
	strings :
		$a_01_0 = {89 45 fc 33 c9 03 4d f0 8b 5d ec 8b 45 f4 } //1
		$a_01_1 = {ff e0 b8 fa 1f 00 00 03 45 e4 } //1
		$a_03_2 = {45 ec 8d 45 fc 50 6a 04 ff 75 f0 ff 75 ec 90 09 01 00 (89|8f) } //1
		$a_01_3 = {58 6a 40 68 00 30 00 00 ff 73 50 ff 73 34 } //1
		$a_03_4 = {50 6a 38 e8 ?? 00 00 00 } //1
		$a_01_5 = {50 90 6a 38 e8 } //1
		$a_01_6 = {b9 e4 c7 f5 8b 81 c1 f9 04 c6 1e } //1
		$a_01_7 = {b9 cd 25 7f 4c 81 c1 10 a7 3c 5e } //1
		$a_01_8 = {81 c1 fd e6 49 6d 81 e9 28 1a 8e c2 } //1
		$a_01_9 = {81 c1 3d e6 49 6d 81 e9 28 1a 8e c2 } //1
		$a_01_10 = {ac aa e2 fc c3 } //1
		$a_03_11 = {c7 45 fc 01 00 00 00 31 03 83 e9 ?? 2b 4d ?? 7c 11 } //1
		$a_01_12 = {c7 45 fc 01 00 00 00 90 31 03 83 c3 04 3b d9 73 0b } //2
		$a_01_13 = {8f 45 f8 c7 45 fc 01 00 00 00 31 03 83 e9 04 7e } //1
		$a_01_14 = {64 a1 30 00 00 00 8b 40 0c 8b 40 1c 8b 4d d0 3b 48 08 74 04 8b 00 eb f7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_03_11  & 1)*1+(#a_01_12  & 1)*2+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=3
 
}