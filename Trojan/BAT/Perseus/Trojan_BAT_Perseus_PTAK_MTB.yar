
rule Trojan_BAT_Perseus_PTAK_MTB{
	meta:
		description = "Trojan:BAT/Perseus.PTAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 97 00 00 70 72 9d 00 00 70 6f 13 00 00 0a 72 a1 00 00 70 72 a7 00 00 70 6f 13 00 00 0a 72 ab 00 00 70 72 b1 00 00 70 6f 13 00 00 0a 28 90 01 01 00 00 0a 13 07 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}