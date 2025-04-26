
rule Trojan_BAT_DarkKomet_UFAA_MTB{
	meta:
		description = "Trojan:BAT/DarkKomet.UFAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 11 06 91 13 05 02 11 06 17 58 91 13 04 11 04 18 5a 06 59 11 05 59 0c 06 11 05 59 11 04 58 0d 02 11 06 09 20 00 01 00 00 5d 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 02 11 06 17 58 08 20 00 01 00 00 5d 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 11 06 18 58 13 06 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}