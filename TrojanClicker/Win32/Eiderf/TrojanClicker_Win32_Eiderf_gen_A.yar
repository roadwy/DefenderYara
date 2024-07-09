
rule TrojanClicker_Win32_Eiderf_gen_A{
	meta:
		description = "TrojanClicker:Win32/Eiderf.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {88 8c 04 08 04 00 00 83 c0 01 3d 00 01 00 00 7c e8 56 57 } //2
		$a_03_1 = {2b c2 83 f8 05 76 33 8b 15 ?? ?? ?? ?? 69 d2 7c 01 00 00 8d 44 24 14 8b c8 2b d1 8d 92 } //2
		$a_01_2 = {54 45 53 54 20 30 36 2e 30 37 2e 31 31 } //1 TEST 06.07.11
		$a_01_3 = {63 6c 69 63 6b 72 61 6e 64 6f 6d 6c 69 6e 6b 3d } //1 clickrandomlink=
		$a_01_4 = {53 00 65 00 72 00 74 00 69 00 66 00 69 00 65 00 64 00 } //1 Sertified
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}