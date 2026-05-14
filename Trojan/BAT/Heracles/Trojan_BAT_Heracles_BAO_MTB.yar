
rule Trojan_BAT_Heracles_BAO_MTB{
	meta:
		description = "Trojan:BAT/Heracles.BAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 08 2c 09 11 06 11 08 17 59 91 2b 04 11 05 1d 91 00 13 0a 11 07 11 08 91 13 0b 11 08 20 ff 00 00 00 5d d2 13 0c 11 06 11 08 91 11 0b 61 11 0a 61 11 0c 61 d2 13 0d 11 09 11 08 11 0d 9c 00 11 08 17 58 13 08 11 08 11 06 8e 69 fe 04 13 11 11 11 2d ac } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Heracles_BAO_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.BAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 17 58 20 00 01 00 00 5d 13 06 11 07 06 11 06 91 58 20 00 01 00 00 5d 13 07 06 11 06 91 13 09 06 11 06 06 11 07 91 9c 06 11 07 11 09 9c 11 05 11 08 02 11 08 91 06 06 11 06 91 06 11 07 91 58 20 00 01 00 00 5d 91 61 d2 9c 11 08 17 58 13 08 11 08 02 8e 69 32 a8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}