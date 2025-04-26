
rule Trojan_Win32_Raccoon_BM_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.BM!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c1 8b 75 08 33 d2 f7 f7 8a 04 32 30 04 19 41 3b 4d 10 72 eb } //10
		$a_01_1 = {50 33 c0 0f 9b c0 52 57 33 ff 0f 9b c0 52 56 33 f6 0f 9b c0 52 33 d0 c1 e2 02 66 c1 e0 62 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}