
rule PWS_Win32_Zbot_gen_AF{
	meta:
		description = "PWS:Win32/Zbot.gen!AF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_01_0 = {81 38 45 52 43 50 74 1a 8d 4d ac 51 6a 00 8d 4d d8 51 e8 } //1
		$a_01_1 = {25 7f 7a fc 23 eb 7e 8b 40 04 eb 79 83 26 00 eb 76 0f b7 40 10 eb 6e } //1
		$a_01_2 = {74 3b 6a 02 68 f0 ae 93 87 e8 } //1
		$a_01_3 = {8b c3 c1 e8 04 f6 d0 24 01 0f b6 c0 c1 eb 03 50 80 e3 01 0f b6 c3 50 e8 } //1
		$a_01_4 = {74 12 66 83 38 5c 75 0c 83 c6 02 66 83 3e 5c 74 f7 89 75 f8 8b cb } //1
		$a_01_5 = {eb 0f 8b cf 6b c9 28 be } //1
		$a_01_6 = {8a 07 3c 21 74 1c 3c 2d 74 14 3c 40 74 0c 3c 5e 74 04 32 db eb 0f b3 04 eb 0a b3 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=3
 
}