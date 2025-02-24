
rule Trojan_BAT_LokiBot_SVCB_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.SVCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 09 07 08 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 11 05 06 16 06 8e 69 6f ?? 00 00 0a 73 ?? 00 00 0a 25 11 04 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}