
rule Trojan_BAT_AveMaria_NEEJ_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 03 8e 69 17 59 17 58 0c 03 04 08 5d 91 07 04 1f 16 5d 91 61 28 ?? 00 00 0a 03 04 17 58 08 5d 91 28 ?? 00 00 0a 59 06 58 06 5d d2 0d 2b 00 09 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}