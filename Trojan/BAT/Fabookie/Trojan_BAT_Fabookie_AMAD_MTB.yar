
rule Trojan_BAT_Fabookie_AMAD_MTB{
	meta:
		description = "Trojan:BAT/Fabookie.AMAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 25 18 6f 90 01 01 00 00 0a 25 18 6f 90 01 01 00 00 0a 25 72 90 01 01 01 00 70 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 16 06 8e 69 6f 90 01 01 00 00 0a 0b 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}