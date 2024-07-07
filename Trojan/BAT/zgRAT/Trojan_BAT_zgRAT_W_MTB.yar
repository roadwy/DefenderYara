
rule Trojan_BAT_zgRAT_W_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.W!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 72 90 01 01 00 00 70 a2 25 18 20 90 01 02 00 00 8c 90 01 01 00 00 01 a2 25 19 7e 90 01 02 00 04 28 90 01 02 00 06 a2 25 1a 20 90 01 02 00 00 8c 90 01 01 00 00 01 a2 25 1b 20 90 01 02 00 00 28 90 01 01 00 00 06 a2 25 1c 02 7b 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}