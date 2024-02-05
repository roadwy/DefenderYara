
rule Trojan_Win32_RedLineStealer_PW_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 ca 89 4c 24 90 01 01 89 5c 24 90 01 01 8b 44 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 54 24 90 01 01 89 54 24 90 01 01 89 1d 90 01 04 8b 44 24 90 01 01 29 44 24 90 01 01 8b 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}