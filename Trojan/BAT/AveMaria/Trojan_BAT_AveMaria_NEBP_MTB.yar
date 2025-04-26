
rule Trojan_BAT_AveMaria_NEBP_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 7e 02 00 00 04 07 7e 02 00 00 04 07 91 20 9e 03 00 00 59 d2 9c 00 07 17 58 0b 07 7e 02 00 00 04 8e 69 fe 04 0c 08 2d d7 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}