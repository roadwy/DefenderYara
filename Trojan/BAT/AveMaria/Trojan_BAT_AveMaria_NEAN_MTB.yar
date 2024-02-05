
rule Trojan_BAT_AveMaria_NEAN_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {7b 2d 00 00 04 28 12 00 00 06 72 d0 15 00 70 72 01 00 00 70 6f 9b 00 00 0a 6f 4a 00 00 0a 00 02 7b 30 00 00 04 02 28 39 00 00 06 6f 4a 00 00 0a 00 7e 27 00 00 04 74 68 00 00 01 6f bc 00 00 0a 16 9a 0a } //00 00 
	condition:
		any of ($a_*)
 
}