
rule Trojan_BAT_AveMaria_NECR_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NECR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 07 11 09 9a 1f 10 28 6e 00 00 0a 8c 58 00 00 01 6f 6f 00 00 0a 26 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0a 11 0a 2d d6 08 d0 58 00 00 01 28 3c 00 00 0a 6f 70 00 00 0a 74 01 00 00 1b 0d 09 28 71 00 00 0a 13 04 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}