
rule Trojan_BAT_Remcos_GQAA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.GQAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 13 00 06 09 06 09 91 20 90 01 02 00 00 59 d2 9c 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d e1 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}