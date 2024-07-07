
rule Trojan_Win32_Raccoon_RB_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 54 24 04 b8 3b 2d 0b 00 01 44 24 04 8b 44 24 04 8a 04 30 88 04 0e 46 3b 35 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 8b 45 90 33 d2 f7 f1 8b 45 88 8b 4d 80 57 8a 04 02 32 04 19 88 03 8d 45 94 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RB_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 c2 08 00 } //1
		$a_03_1 = {8b c6 c1 e0 04 03 45 90 01 01 33 45 90 01 01 33 45 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Raccoon_RB_MTB_4{
	meta:
		description = "Trojan:Win32/Raccoon.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 c1 e1 04 03 4c 24 90 01 01 89 4c 24 90 01 01 8d 0c 07 c1 e8 05 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 01 33 c1 33 44 24 90 02 12 2b f0 89 44 24 90 01 01 8b c6 c1 e0 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RB_MTB_5{
	meta:
		description = "Trojan:Win32/Raccoon.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 83 65 fc 00 8b 45 10 01 45 fc 8b 45 0c 33 45 fc 89 45 fc 8b 45 08 8b 4d fc 89 08 c9 c2 0c 00 90 02 25 55 8b ec 51 c7 45 fc 02 00 00 00 83 45 fc 02 8b 4d fc 8b 45 0c d3 e0 8b 4d 08 89 01 c9 c2 08 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}