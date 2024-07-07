
rule Trojan_Win32_Raccoon_QV_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.QV!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 45 f0 f6 d0 30 44 0d f1 41 83 f9 0e 72 f1 } //10
		$a_01_1 = {30 8c 15 21 fd ff ff 42 83 fa 07 73 08 8a 8d 20 fd ff ff eb eb } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}