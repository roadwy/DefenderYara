
rule Trojan_BAT_LokiBot_SPBF_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.SPBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 59 7e 0e 00 00 04 8e 69 5d 13 0a 02 11 09 91 13 0b 08 18 5d 16 fe 01 13 0c 11 0c 2c 14 00 06 11 09 11 0b 7e 0e 00 00 04 11 0a 91 59 d2 9c 00 2b 12 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}