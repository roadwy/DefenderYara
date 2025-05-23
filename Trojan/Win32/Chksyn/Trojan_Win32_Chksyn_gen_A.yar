
rule Trojan_Win32_Chksyn_gen_A{
	meta:
		description = "Trojan:Win32/Chksyn.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {c7 45 e8 00 00 00 00 83 7d e4 00 75 0a b8 0f 00 00 c0 e9 91 00 00 00 83 7d ec 00 75 10 8b 55 e4 83 c2 64 } //1
		$a_02_1 = {50 8b 4d f0 83 c1 04 51 e8 ?? 23 00 00 83 c4 08 85 c0 74 07 c7 45 f4 34 00 00 c0 68 ?? ?? ?? ?? 6a 00 } //1
		$a_03_2 = {74 4e 68 00 01 00 00 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? b8 ?? ?? ?? ?? 99 52 50 68 76 01 00 00 e8 ?? ?? ff ff 85 c0 74 17 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}
rule Trojan_Win32_Chksyn_gen_A_2{
	meta:
		description = "Trojan:Win32/Chksyn.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 12 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 0a 30 0c 06 } //1
		$a_01_1 = {8b 40 0c 8b 40 1c 8b 00 } //1
		$a_03_2 = {8b 70 1c ad 8b 40 08 (5e|e9) } //1
		$a_01_3 = {8b 34 9a 5a 5b } //1
		$a_01_4 = {8b 04 9a 5a 5b } //1
		$a_03_5 = {8b 40 30 83 b8 b0 00 00 00 02 0f (84|85) } //1
		$a_01_6 = {33 d2 64 89 25 00 00 00 00 ff 12 } //1
		$a_01_7 = {68 3f 26 cb 10 e8 } //1
		$a_01_8 = {68 b9 2c ff e6 89 7d f8 } //1
		$a_01_9 = {68 44 a6 ca 0b e8 } //1
		$a_01_10 = {68 83 8e f1 66 e8 } //1
		$a_01_11 = {68 7e 18 ba ce e8 } //1
		$a_01_12 = {c6 00 8b e8 } //1
		$a_01_13 = {68 b5 7e 38 c6 89 45 } //2
		$a_01_14 = {68 f8 32 31 c6 e8 } //2
		$a_01_15 = {c6 00 c3 ff 14 24 } //2
		$a_01_16 = {8b 45 08 c6 00 b8 } //2
		$a_01_17 = {89 48 01 66 c7 40 05 ff e0 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*2+(#a_01_14  & 1)*2+(#a_01_15  & 1)*2+(#a_01_16  & 1)*2+(#a_01_17  & 1)*2) >=5
 
}