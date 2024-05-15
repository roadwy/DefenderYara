
rule Trojan_BAT_Heracles_JRAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.JRAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 06 09 5d 91 07 06 1f 16 5d 6f 90 01 01 00 00 0a 61 13 0d 11 0d 11 0c 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0e 08 06 09 5d 11 0e 28 90 01 01 00 00 0a d2 9c 06 17 58 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}