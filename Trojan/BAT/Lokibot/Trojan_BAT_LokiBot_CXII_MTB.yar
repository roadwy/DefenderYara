
rule Trojan_BAT_LokiBot_CXII_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CXII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 08 11 04 11 08 18 5a 18 6f ?? ?? ?? ?? 1f 10 28 ?? ?? ?? ?? d2 9c 00 11 08 17 58 13 08 11 08 11 05 8e 69 fe 04 13 09 11 09 2d d1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}