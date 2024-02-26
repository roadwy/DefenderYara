
rule Trojan_Win32_RedLineStealer_P_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {80 07 48 33 90 01 11 80 2f 97 33 90 01 11 f6 2f 47 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}