
rule Trojan_BAT_LokiBot_CXIT_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CXIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 5b 00 00 70 0a 06 28 0d 00 00 0a 0b 28 3e 00 00 0a 25 26 07 16 07 8e 69 6f 62 00 00 0a 25 26 0a 28 13 00 00 0a 25 26 06 6f 3f 00 00 0a 25 26 0c 1f 61 6a 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}