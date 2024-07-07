
rule Trojan_BAT_LokiBot_CLQ_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CLQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 9d 02 00 70 6f 90 01 04 74 90 01 04 72 90 01 04 72 90 01 04 6f 90 01 04 17 8d 90 01 04 25 16 1f 2d 9d 6f 90 01 04 13 04 11 04 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}