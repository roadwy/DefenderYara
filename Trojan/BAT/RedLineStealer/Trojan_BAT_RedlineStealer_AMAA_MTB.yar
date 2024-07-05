
rule Trojan_BAT_RedlineStealer_AMAA_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 09 08 91 09 07 91 58 20 00 01 00 00 5d 13 90 01 01 03 11 90 01 01 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 09 11 90 01 01 91 61 d2 81 90 01 01 00 00 01 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}