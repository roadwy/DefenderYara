
rule Trojan_Win32_Bunitucrypt_DE_MTB{
	meta:
		description = "Trojan:Win32/Bunitucrypt.DE!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {2d 00 10 00 00 83 c0 04 } //10
		$a_01_1 = {57 89 c7 88 cd 89 c8 c1 e0 10 66 89 c8 89 d1 c1 f9 02 78 09 f3 ab 89 d1 83 e1 03 f3 aa 5f c3 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}