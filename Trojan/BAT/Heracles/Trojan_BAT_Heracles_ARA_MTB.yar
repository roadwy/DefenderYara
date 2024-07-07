
rule Trojan_BAT_Heracles_ARA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 8e 69 5d 7e 90 01 03 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 03 06 03 08 1b 58 1a 59 03 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 03 8e 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Heracles_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 0a 74 90 01 03 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 75 90 01 03 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f 90 01 03 0a 26 11 0f 1f 60 91 20 c6 00 00 00 59 13 0e 38 90 00 } //2
		$a_03_1 = {13 04 11 0a 74 90 01 03 1b 11 0c 93 13 05 11 0a 74 90 01 03 1b 11 0c 17 58 93 11 05 61 13 06 1e 13 0e 38 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}