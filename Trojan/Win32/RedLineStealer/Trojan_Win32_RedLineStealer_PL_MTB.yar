
rule Trojan_Win32_RedLineStealer_PL_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 20 89 44 24 14 8b 44 24 24 01 44 24 14 8b 44 24 20 c1 e8 90 01 01 89 44 24 10 8b 44 24 38 03 44 24 10 c7 05 90 01 08 33 44 24 14 33 c6 81 3d 8c 92 63 00 90 01 04 89 44 24 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}