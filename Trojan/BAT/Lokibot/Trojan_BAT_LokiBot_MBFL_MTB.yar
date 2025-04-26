
rule Trojan_BAT_LokiBot_MBFL_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.MBFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 0d 07 06 17 58 09 5d 91 13 0e 11 0c 11 0d 61 11 0e 59 20 00 01 00 00 58 13 0f 07 11 06 11 0f 20 00 01 00 00 5d d2 9c 06 17 59 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}