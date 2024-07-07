
rule Trojan_Win32_Raccoon_RD_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 55 f8 89 4d fc 8b 45 f8 c1 e0 04 8b 4d fc 89 01 8b e5 5d c3 } //1
		$a_01_1 = {8b 55 e4 33 55 f0 89 55 e4 8b 45 e4 33 45 ec 89 45 e4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Raccoon_RD_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 45 fc 83 6d fc 02 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 8b 44 24 04 8b 4c 24 08 01 08 c2 08 00 8b 44 24 08 8b 4c 24 04 c1 e0 04 89 01 c2 08 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RD_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 10 01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 c2 08 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RD_MTB_4{
	meta:
		description = "Trojan:Win32/Raccoon.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 83 65 fc 00 8b 45 0c 01 45 fc 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 0c 33 45 fc 89 45 fc 8b 45 08 8b 4d fc 89 08 c9 c2 0c 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}