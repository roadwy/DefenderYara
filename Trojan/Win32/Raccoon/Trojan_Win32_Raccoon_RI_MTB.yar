
rule Trojan_Win32_Raccoon_RI_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 c7 45 fc 04 00 00 00 8b 45 0c 83 6d fc 04 01 45 fc 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RI_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 0c 90 01 45 fc 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RI_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 10 01 45 fc 8b 45 08 8b 4d fc 89 08 c9 c2 0c 00 c2 08 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RI_MTB_4{
	meta:
		description = "Trojan:Win32/Raccoon.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c2 08 00 81 01 e1 34 ef c6 c3 } //1
		$a_03_1 = {d3 e8 c7 05 90 01 04 ee 3d ea f4 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 02 70 81 6d 90 01 01 36 dd 96 53 81 45 90 01 01 3a dd 96 53 8b 45 90 01 01 8b 4d 90 01 01 d3 e0 90 02 30 d3 e8 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 33 45 90 02 09 31 45 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}