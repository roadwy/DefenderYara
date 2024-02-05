
rule Trojan_Win32_Dofoil_VSD_MTB{
	meta:
		description = "Trojan:Win32/Dofoil.VSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {23 c7 81 3d 90 01 04 21 06 00 00 a3 90 01 04 75 90 09 12 00 a1 90 01 04 0f b6 80 90 01 04 03 05 90 00 } //01 00 
		$a_02_1 = {30 04 37 4e 79 90 09 05 00 e8 90 00 } //02 00 
		$a_02_2 = {8b f5 c1 ee 05 03 74 24 34 33 c7 81 3d 90 01 04 b4 11 00 00 89 44 24 10 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}