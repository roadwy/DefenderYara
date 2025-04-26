
rule Trojan_BAT_DarkKomet_AAUH_MTB{
	meta:
		description = "Trojan:BAT/DarkKomet.AAUH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 07 11 0f 02 11 0f 91 11 04 61 11 08 11 0a 91 61 b4 9c 11 0a 03 6f ?? 00 00 0a 17 da 33 05 16 13 0a 2b 06 11 0a 17 d6 13 0a 11 0f 17 d6 13 0f 11 0f 11 10 31 ca } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}