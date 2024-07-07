
rule Trojan_BAT_LokiBot_CMM_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 08 09 91 28 05 00 00 06 13 04 7e 01 00 00 04 11 04 6f 0d 00 00 0a 09 17 58 0d 09 08 8e 69 17 59 32 dd } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}