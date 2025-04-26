
rule Trojan_Win32_Raccoon_RM_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e1 34 ef c6 c3 } //1
		$a_03_1 = {ee 3d ea f4 [0-10] 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 [0-60] 81 6d ?? 36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-35] 89 45 ?? 8b 45 ?? 01 45 ?? 8b ?? ?? 33 [0-09] 31 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Raccoon_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 00 e1 34 ef c6 c3 } //1
		$a_03_1 = {ee 3d ea f4 89 45 [0-10] 33 5d ?? 31 5d ?? 81 3d [0-60] 81 6d ?? 36 dd 96 53 81 45 ?? 3a dd 96 53 8b 45 ?? 8b 4d ?? 03 c7 8b d7 d3 e2 [0-10] d3 e8 [0-10] 01 45 ?? 8b 45 ?? 33 45 [0-08] 33 d0 [0-08] 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}