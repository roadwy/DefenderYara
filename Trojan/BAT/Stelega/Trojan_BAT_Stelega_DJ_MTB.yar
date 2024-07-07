
rule Trojan_BAT_Stelega_DJ_MTB{
	meta:
		description = "Trojan:BAT/Stelega.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {16 0a 2b 13 03 06 03 06 91 06 20 48 0a 00 00 5d 61 d2 9c 06 17 58 0a 06 03 8e 69 32 e7 02 03 7d 90 01 03 04 1f 58 2a 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}