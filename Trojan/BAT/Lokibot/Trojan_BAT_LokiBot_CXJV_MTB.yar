
rule Trojan_BAT_LokiBot_CXJV_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CXJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 08 11 0a 58 11 09 11 0b 58 6f ?? ?? ?? ?? 13 0c 12 0c 28 ?? ?? ?? ?? 13 0d 11 04 11 06 11 0d 9c 11 06 17 58 13 06 00 11 0b 17 58 13 0b 11 0b 17 fe 04 13 0e 11 0e 2d c4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}