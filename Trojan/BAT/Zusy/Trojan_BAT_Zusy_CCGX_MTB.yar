
rule Trojan_BAT_Zusy_CCGX_MTB{
	meta:
		description = "Trojan:BAT/Zusy.CCGX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 16 11 17 9a 13 18 00 11 18 28 90 01 01 00 00 0a 13 19 11 19 2c 14 09 6f 90 01 01 00 00 0a 11 18 73 90 01 04 6f 90 01 01 00 00 0a 00 00 00 de 10 25 28 90 01 01 00 00 0a 13 1a 00 28 90 01 01 00 00 0a de 00 00 00 11 17 17 d6 13 17 11 17 11 16 8e 69 fe 04 13 1b 11 1b 2d ae 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}