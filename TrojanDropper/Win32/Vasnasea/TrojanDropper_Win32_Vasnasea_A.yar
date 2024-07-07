
rule TrojanDropper_Win32_Vasnasea_A{
	meta:
		description = "TrojanDropper:Win32/Vasnasea.A,SIGNATURE_TYPE_PEHSTR_EXT,14 00 12 00 08 00 00 "
		
	strings :
		$a_01_0 = {ba 02 02 02 02 39 54 03 fc 75 07 83 e9 01 8b e8 74 08 40 8d 70 fc 3b f7 72 eb 8d 44 24 18 } //8
		$a_01_1 = {75 0d 8b 47 0c 03 45 08 03 c3 80 30 2a eb 39 } //8
		$a_01_2 = {8b 4f 0c 03 4d 08 80 3c 19 c3 74 11 83 f8 03 75 10 8b 4f 0c 03 4d 08 80 3c 19 c2 } //4
		$a_01_3 = {38 39 37 32 33 34 6b 6a 64 73 66 34 35 32 33 32 33 34 2e 63 6f 6d } //2 897234kjdsf4523234.com
		$a_01_4 = {5c 5c 2e 5c 70 69 70 65 5c 6d 73 70 69 70 65 5f 6f 67 } //2 \\.\pipe\mspipe_og
		$a_01_5 = {64 61 6f 37 65 72 6d 73 5f 61 } //2 dao7erms_a
		$a_01_6 = {89 46 14 80 fa 3c 74 21 8b 46 14 83 c0 ff 78 07 3b c7 7d 03 89 46 14 8b 46 14 } //4
		$a_01_7 = {c6 04 08 e9 8b 13 8b ce 2b c8 83 e9 05 89 4c 02 01 8d 4d fc } //4
	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*8+(#a_01_2  & 1)*4+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*4+(#a_01_7  & 1)*4) >=18
 
}