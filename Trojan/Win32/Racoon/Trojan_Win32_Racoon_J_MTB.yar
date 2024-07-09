
rule Trojan_Win32_Racoon_J_MTB{
	meta:
		description = "Trojan:Win32/Racoon.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 01 c3 31 08 c3 33 44 24 04 c2 04 00 81 00 cc 36 ef c6 c3 [0-05] 29 08 c3 } //1
		$a_03_1 = {8b c2 d3 e0 [0-20] 8b c2 c1 e8 05 [0-20] 03 c2 50 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}