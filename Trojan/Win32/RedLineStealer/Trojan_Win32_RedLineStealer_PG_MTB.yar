
rule Trojan_Win32_RedLineStealer_PG_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 24 89 44 24 18 8b 44 24 10 01 44 24 18 8b 44 24 24 c1 e8 90 01 01 89 44 24 14 8b 44 24 14 03 44 24 40 c7 05 90 02 08 33 44 24 18 33 c6 81 3d 90 02 08 89 44 24 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}