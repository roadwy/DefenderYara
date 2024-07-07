
rule Trojan_Win32_Raccoon_AM_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 c7 04 24 02 00 00 00 8b 44 24 08 90 01 04 24 83 2c 24 02 8b 04 24 31 01 59 c2 04 00 } //10
		$a_01_1 = {8b 44 24 14 29 44 24 18 8b 4c 24 18 c1 e1 04 89 4c 24 10 8b 44 24 2c 01 44 24 10 8b 44 24 18 03 44 24 20 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}