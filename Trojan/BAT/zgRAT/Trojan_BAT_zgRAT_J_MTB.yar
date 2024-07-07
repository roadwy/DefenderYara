
rule Trojan_BAT_zgRAT_J_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 70 20 00 01 00 00 14 14 14 6f 90 09 14 00 06 13 90 01 01 72 90 01 01 00 00 70 28 90 01 01 00 00 06 11 90 01 01 8e 69 26 72 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}