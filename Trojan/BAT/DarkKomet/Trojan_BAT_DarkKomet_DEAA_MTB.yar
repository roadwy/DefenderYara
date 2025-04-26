
rule Trojan_BAT_DarkKomet_DEAA_MTB{
	meta:
		description = "Trojan:BAT/DarkKomet.DEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 11 08 03 11 08 91 06 11 08 07 5d 91 61 9c 00 11 08 17 d6 13 08 11 08 11 0b 31 e4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}