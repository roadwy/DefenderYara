
rule Trojan_Win32_RedLineStealer_PA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 75 ec 8b 45 e8 01 45 ec 8b 45 e4 01 45 ec 8b 45 ec 89 45 f4 8b 45 e4 8b 4d f0 d3 e8 89 45 fc 8b 45 cc 01 45 fc 8b 5d e4 c1 e3 90 01 01 03 5d d8 33 5d f4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLineStealer_PA_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 b9 0a 00 00 00 f7 f1 0f b6 92 90 01 04 8b 45 90 01 01 03 45 90 01 01 0f b6 08 33 ca 8b 55 90 01 01 03 55 90 01 01 88 0a ff 15 90 01 04 89 45 90 01 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}