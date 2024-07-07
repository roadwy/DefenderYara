
rule Trojan_BAT_zgRAT_N_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 08 11 04 91 72 90 01 02 00 70 11 04 72 90 01 02 00 70 28 90 01 02 00 0a 5d 28 90 01 02 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 08 8e 69 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}