
rule Trojan_BAT_AveMaria_RPY_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 06 09 11 06 91 20 37 07 00 00 59 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 32 e4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AveMaria_RPY_MTB_2{
	meta:
		description = "Trojan:BAT/AveMaria.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 11 15 09 5d 13 16 11 15 11 04 5d 13 17 07 11 16 91 13 18 08 11 17 } //1
		$a_01_1 = {13 1b 07 11 16 11 1b 20 00 01 00 00 5d d2 9c 00 11 15 17 59 13 15 11 15 16 fe 04 16 fe 01 13 1c 11 1c 2d a9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}