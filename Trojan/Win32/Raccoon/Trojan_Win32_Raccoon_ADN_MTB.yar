
rule Trojan_Win32_Raccoon_ADN_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.ADN!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 04 89 01 c3 33 44 24 04 89 01 c2 04 00 33 44 24 04 c2 04 00 81 00 a4 36 ef c6 c3 01 08 c3 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}