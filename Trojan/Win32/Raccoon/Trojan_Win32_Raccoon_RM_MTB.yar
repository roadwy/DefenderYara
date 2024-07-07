
rule Trojan_Win32_Raccoon_RM_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e1 34 ef c6 c3 } //1
		$a_03_1 = {ee 3d ea f4 90 02 10 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 02 60 81 6d 90 01 01 36 dd 96 53 81 45 90 01 01 3a dd 96 53 8b 90 02 35 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 90 01 02 33 90 02 09 31 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Raccoon_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 00 e1 34 ef c6 c3 } //1
		$a_03_1 = {ee 3d ea f4 89 45 90 02 10 33 5d 90 01 01 31 5d 90 01 01 81 3d 90 02 60 81 6d 90 01 01 36 dd 96 53 81 45 90 01 01 3a dd 96 53 8b 45 90 01 01 8b 4d 90 01 01 03 c7 8b d7 d3 e2 90 02 10 d3 e8 90 02 10 01 45 90 01 01 8b 45 90 01 01 33 45 90 02 08 33 d0 90 02 08 29 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}