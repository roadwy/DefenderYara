
rule Trojan_Win32_Raccoon_RK_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 c2 08 00 55 8b ec 8b 4d 08 8b 01 89 45 08 8b 45 0c 01 45 08 8b 45 0c 01 01 5d c2 08 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RK_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {29 11 c3 cc 90 02 15 81 01 e1 34 ef c6 c3 90 00 } //1
		$a_01_1 = {01 44 24 20 8b 44 24 20 89 44 24 28 8b 44 24 18 8b 4c 24 1c d3 e8 89 44 24 14 8b 44 24 40 01 44 24 14 8b 4c 24 14 33 4c 24 28 8b 44 24 10 33 c1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}