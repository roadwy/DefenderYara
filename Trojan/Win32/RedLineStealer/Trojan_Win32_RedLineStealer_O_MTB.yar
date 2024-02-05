
rule Trojan_Win32_RedLineStealer_O_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.O!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {80 2f 88 33 90 01 05 80 07 49 90 01 06 f6 2f 47 e2 90 00 } //02 00 
		$a_03_1 = {80 2f 88 8b 90 01 01 33 90 01 03 80 07 49 90 01 02 8b 90 01 03 f6 2f 47 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}