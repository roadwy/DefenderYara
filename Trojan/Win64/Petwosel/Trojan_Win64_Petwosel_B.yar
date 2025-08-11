
rule Trojan_Win64_Petwosel_B{
	meta:
		description = "Trojan:Win64/Petwosel.B,SIGNATURE_TYPE_PEHSTR_EXT,ffffff84 00 ffffff84 00 08 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //100
		$a_03_1 = {b8 4d 5a 00 00 [0-1a] 81 3f 50 45 00 00 } //10
		$a_03_2 = {3c 02 0f 84 ?? 00 00 00 3c 03 75 ?? b8 00 20 00 00 66 85 ?? 16 0f 84 ?? 00 00 00 } //10
		$a_01_3 = {41 ff 16 48 8b e8 48 85 c0 74 62 8b 7b 10 48 03 fe eb 26 79 05 0f b7 d1 eb 07 48 8d 56 02 48 03 d1 48 85 d2 74 47 48 8b cd 41 ff 56 08 } //10
		$a_01_4 = {b9 02 9f e6 6a } //1
		$a_01_5 = {ba 8d bd c1 3f } //1
		$a_01_6 = {ba ff 1f 7c c9 } //1
		$a_01_7 = {41 81 f0 20 83 b8 ed } //1
	condition:
		((#a_01_0  & 1)*100+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=132
 
}