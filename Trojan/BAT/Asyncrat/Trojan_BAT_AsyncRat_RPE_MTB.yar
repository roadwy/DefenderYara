
rule Trojan_BAT_AsyncRat_RPE_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 04 72 01 00 00 70 28 90 01 01 00 00 0a 2d 31 11 04 72 05 00 00 70 28 90 01 01 00 00 0a 2d 60 11 04 72 0b 00 00 70 28 90 01 01 00 00 0a 3a cf 00 00 00 11 04 72 0f 00 00 70 28 90 01 01 00 00 0a 3a 0b 01 00 00 2a 72 09 00 00 70 0a 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}