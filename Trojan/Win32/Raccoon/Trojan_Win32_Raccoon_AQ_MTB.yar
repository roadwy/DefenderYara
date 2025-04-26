
rule Trojan_Win32_Raccoon_AQ_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 44 24 04 c2 04 00 81 00 4a 36 ef c6 c3 01 08 c3 } //10
		$a_01_1 = {c1 e0 04 89 01 c3 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}