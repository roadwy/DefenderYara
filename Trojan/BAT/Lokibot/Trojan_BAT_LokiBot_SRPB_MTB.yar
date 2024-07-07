
rule Trojan_BAT_LokiBot_SRPB_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.SRPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 1f 16 5d 91 61 28 90 01 03 0a 02 07 17 58 02 8e 69 5d 91 28 90 01 03 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 07 15 58 0b 07 16 2f c2 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}