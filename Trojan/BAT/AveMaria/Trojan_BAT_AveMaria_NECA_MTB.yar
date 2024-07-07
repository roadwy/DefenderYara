
rule Trojan_BAT_AveMaria_NECA_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NECA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 37 00 00 0a 02 07 17 58 02 8e 69 5d 91 28 38 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 2d b8 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}