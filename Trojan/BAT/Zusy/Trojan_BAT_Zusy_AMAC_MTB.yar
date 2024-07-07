
rule Trojan_BAT_Zusy_AMAC_MTB{
	meta:
		description = "Trojan:BAT/Zusy.AMAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 08 11 04 03 11 04 91 07 61 06 09 91 61 d2 9c 09 04 6f 90 01 01 00 00 0a 17 59 fe 01 13 05 11 05 2c 04 16 0d 2b 04 09 17 58 0d 00 11 04 17 58 13 04 11 04 03 8e 69 fe 04 13 06 11 06 2d c3 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}