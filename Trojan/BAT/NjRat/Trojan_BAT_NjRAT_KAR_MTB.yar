
rule Trojan_BAT_NjRAT_KAR_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.KAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 04 08 11 04 91 09 61 d2 9c 09 20 90 01 01 00 00 00 5a 20 00 01 00 00 5d d2 0d 11 04 17 58 13 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}