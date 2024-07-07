
rule Trojan_BAT_AveMaria_NECQ_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NECQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 06 11 08 9a 1f 10 28 74 00 00 0a 8c 54 00 00 01 6f 75 00 00 0a 26 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d d6 07 d0 54 00 00 01 28 50 00 00 0a 6f 76 00 00 0a 74 03 00 00 1b 0c 28 77 00 00 0a 08 6f 78 00 00 0a 0d 09 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}