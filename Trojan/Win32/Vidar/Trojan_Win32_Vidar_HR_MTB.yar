
rule Trojan_Win32_Vidar_HR_MTB{
	meta:
		description = "Trojan:Win32/Vidar.HR!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d0 c1 ea 05 03 54 24 24 03 cd 33 d1 03 c6 33 d0 2b fa } //01 00 
		$a_01_1 = {33 f3 31 74 24 14 8b 44 24 14 29 44 24 18 } //00 00 
	condition:
		any of ($a_*)
 
}