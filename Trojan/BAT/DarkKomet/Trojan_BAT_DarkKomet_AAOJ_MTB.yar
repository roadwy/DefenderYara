
rule Trojan_BAT_DarkKomet_AAOJ_MTB{
	meta:
		description = "Trojan:BAT/DarkKomet.AAOJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 60 05 00 8d 90 01 01 00 00 01 25 d0 90 01 01 00 00 04 28 90 01 01 00 00 06 0a 2b 07 28 90 01 01 00 00 06 2b e1 06 16 06 8e 69 28 90 01 01 00 00 06 2b 07 28 90 01 01 00 00 0a 2b cb 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}