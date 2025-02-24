
rule Trojan_BAT_LokiBot_SDGB_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.SDGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 19 8d 3b 00 00 01 25 16 07 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 07 1e 63 20 ff 00 00 00 5f d2 9c 25 18 07 20 ff 00 00 00 5f d2 9c 6f ?? 01 00 0a 09 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}