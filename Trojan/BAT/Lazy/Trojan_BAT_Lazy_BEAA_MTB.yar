
rule Trojan_BAT_Lazy_BEAA_MTB{
	meta:
		description = "Trojan:BAT/Lazy.BEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 00 11 06 08 6f 90 01 01 00 00 0a 00 11 06 17 6f 90 01 01 00 00 0a 00 11 06 09 6f 90 01 01 00 00 0a 00 11 06 18 6f 90 01 01 00 00 0a 00 11 06 6f 90 01 01 00 00 0a 13 07 11 07 06 16 06 8e 69 6f 90 01 01 00 00 0a 73 90 01 01 00 00 0a 16 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}