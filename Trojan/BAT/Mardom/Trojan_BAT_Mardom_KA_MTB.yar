
rule Trojan_BAT_Mardom_KA_MTB{
	meta:
		description = "Trojan:BAT/Mardom.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 2d 1d 06 09 11 04 09 8e 69 5d 91 08 11 04 91 61 d2 6f 90 01 01 00 00 0a 11 04 17 58 1d 2c de 13 04 11 04 08 8e 69 32 d9 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}