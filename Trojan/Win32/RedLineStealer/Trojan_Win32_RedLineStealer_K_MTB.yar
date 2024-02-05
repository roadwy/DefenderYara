
rule Trojan_Win32_RedLineStealer_K_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {f7 e2 c1 ea 90 01 01 8b ca c1 e1 90 01 01 03 ca 8b 54 24 90 01 01 8b c2 2b c1 8a 80 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}