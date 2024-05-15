
rule Trojan_BAT_RiseProStealer_HWAA_MTB{
	meta:
		description = "Trojan:BAT/RiseProStealer.HWAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 13 11 13 7b 90 01 01 00 00 04 17 58 20 00 01 00 00 5d 90 00 } //02 00 
		$a_03_1 = {05 11 0c 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 11 02 11 0e 91 61 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}