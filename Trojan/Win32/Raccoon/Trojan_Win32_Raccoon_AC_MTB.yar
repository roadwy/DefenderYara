
rule Trojan_Win32_Raccoon_AC_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.AC!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 44 24 04 c2 04 00 81 00 ae 36 ef c6 c3 01 08 c3 } //10
		$a_01_1 = {8b 4d f4 89 45 f8 8b c6 d3 e8 03 45 d8 33 45 f8 2b f8 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}