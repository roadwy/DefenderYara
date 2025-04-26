
rule Trojan_Win32_Sehijak_A{
	meta:
		description = "Trojan:Win32/Sehijak.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {8b c1 c1 e8 0b 33 c8 8b c1 25 ad 58 3a ff c1 e0 07 33 c8 8b c1 25 8c df ff ff c1 e0 0f 33 c8 8b c1 c1 e8 12 33 c1 } //4
		$a_01_1 = {1e 9f 8d d2 44 24 e6 b2 df b6 53 1c 72 43 3e 18 1c ed 46 52 70 1d 7a 82 7a d3 a5 ec 29 cf 15 bd } //1
		$a_01_2 = {4f 4e f4 38 9c f8 15 61 2e 20 37 46 f9 1e cc c8 17 a6 00 } //1
		$a_01_3 = {9c e9 17 a3 12 a9 48 03 25 64 1b 4e f0 a9 89 49 72 5d 05 c3 e4 e4 a2 f3 42 45 bd 4e a7 e7 83 78 68 dc 00 } //1
		$a_01_4 = {05 a8 e0 2b 9f b6 25 11 2f c2 87 1a 68 a5 12 73 14 5a 00 } //1
		$a_01_5 = {de be 81 ee de 78 14 a8 35 21 53 17 84 a0 c0 00 } //1
		$a_01_6 = {85 f1 fc 3e 9b 4d 62 c4 1d 77 9f f6 73 91 00 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}