
rule Trojan_Win32_Dorv_A_MTB{
	meta:
		description = "Trojan:Win32/Dorv.A!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d bd 35 f2 ff ff 88 9d 34 f2 ff ff f3 ab 66 ab aa 8b ce 33 c0 8d bd 2d f0 ff ff 88 9d 2c f0 ff ff f3 ab 66 ab aa 8b ce } //10
		$a_01_1 = {8a d8 8a fb 8b d1 8b c3 c1 e0 10 66 8b c3 5b c1 e9 02 f3 ab } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}