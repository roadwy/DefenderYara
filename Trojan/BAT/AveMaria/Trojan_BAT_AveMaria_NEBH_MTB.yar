
rule Trojan_BAT_AveMaria_NEBH_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 7e bf 00 00 04 09 7e bf 00 00 04 09 91 20 a1 02 00 00 59 d2 9c 00 09 17 58 0d 09 7e bf 00 00 04 8e 69 fe 04 13 04 11 04 2d d5 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}