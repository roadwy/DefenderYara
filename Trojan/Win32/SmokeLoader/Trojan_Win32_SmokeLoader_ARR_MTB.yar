
rule Trojan_Win32_SmokeLoader_ARR_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {23 e9 30 d0 b1 ?? e5 ?? bd ?? ?? ?? ?? 18 63 ?? 96 85 17 b2 5b } //10
		$a_01_1 = {20 14 72 f3 1b 4d af 89 f0 84 28 2f fa 2d } //8
		$a_01_2 = {97 a5 2a 24 97 5d a1 } //2
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*8+(#a_01_2  & 1)*2) >=20
 
}
rule Trojan_Win32_SmokeLoader_ARR_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 06 00 00 "
		
	strings :
		$a_03_0 = {0e cc d0 5c 66 c7 d7 80 32 ?? d0 b4 c5 } //12
		$a_03_1 = {86 23 5f 8c cd 30 6d ?? 23 83 ?? ?? ?? ?? 09 f2 b6 } //8
		$a_03_2 = {ac 92 94 25 ?? ?? ?? ?? aa 92 99 25 } //12
		$a_01_3 = {c4 36 a7 aa 5f 30 3a a6 fe c9 a1 } //8
		$a_03_4 = {12 ce 4f 3a 10 d0 b7 ?? ?? ?? ?? 31 68 cf } //12
		$a_03_5 = {53 08 04 9f 12 1d ?? ?? ?? ?? 33 e3 4f 67 b3 } //8
	condition:
		((#a_03_0  & 1)*12+(#a_03_1  & 1)*8+(#a_03_2  & 1)*12+(#a_01_3  & 1)*8+(#a_03_4  & 1)*12+(#a_03_5  & 1)*8) >=20
 
}