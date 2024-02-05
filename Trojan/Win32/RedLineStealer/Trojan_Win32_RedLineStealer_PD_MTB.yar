
rule Trojan_Win32_RedLineStealer_PD_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 45 0c 8b 45 ec 01 45 0c 8b 45 e8 83 25 90 01 05 03 c8 8d 04 3b 33 c8 31 4d 0c 8b 45 0c 01 05 90 01 04 2b 75 0c 83 0d 90 01 05 8b c6 c1 e8 90 01 01 03 45 f4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLineStealer_PD_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c7 33 f0 33 75 90 01 01 89 75 90 01 01 8b 45 90 01 01 01 05 90 01 04 83 0d 90 01 04 ff 2b de 8b c3 c1 e0 04 03 45 90 01 01 8b d3 89 45 90 01 01 8d 04 1f 50 8d 45 90 01 01 c1 ea 05 03 55 90 01 01 50 c7 05 90 01 04 b4 21 e1 c5 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}