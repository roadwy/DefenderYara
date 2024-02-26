
rule Trojan_Win32_RedLineStealer_PN_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 44 24 90 01 01 8b 44 24 90 01 01 03 44 24 90 01 01 c7 05 90 01 08 33 44 24 90 01 01 33 c6 81 3d 90 01 08 89 44 24 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}