
rule Trojan_BAT_LokiBot_CMO_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {04 05 5d 91 61 7e 1a 01 00 04 28 5b 02 00 06 03 04 17 58 03 8e 69 5d 91 7e 1b 01 00 04 28 5f 02 00 06 59 11 00 58 11 00 5d d2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}