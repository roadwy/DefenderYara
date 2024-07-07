
rule Trojan_BAT_LokiBot_ARA_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 20 00 01 00 00 13 16 09 17 58 13 17 09 11 04 5d 13 18 11 17 11 04 5d 13 19 07 11 19 91 11 16 58 13 1a 07 11 18 91 13 1b 08 09 1f 16 5d 91 13 1c 11 1b 11 1c 61 13 1d 11 1d 11 1a 59 13 1e 07 11 18 11 1e 11 16 5d d2 9c 09 17 58 0d 00 09 11 04 fe 04 13 1f 11 1f 2d a7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}