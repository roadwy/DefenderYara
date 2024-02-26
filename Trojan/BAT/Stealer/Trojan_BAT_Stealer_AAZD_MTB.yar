
rule Trojan_BAT_Stealer_AAZD_MTB{
	meta:
		description = "Trojan:BAT/Stealer.AAZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 09 06 07 09 59 17 59 91 9c 16 } //02 00 
		$a_01_1 = {06 07 09 59 17 59 11 04 9c 09 17 58 16 2d c2 } //00 00 
	condition:
		any of ($a_*)
 
}