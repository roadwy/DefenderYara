
rule Trojan_BAT_Agenttesla_ARAJ_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.ARAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 20 00 01 00 00 13 18 11 17 17 58 13 19 11 17 20 00 ba 00 00 5d 13 1a 11 19 20 00 ba 00 00 5d 13 1b 08 11 1a 91 13 1c 09 11 17 1f 16 5d 91 13 1d 08 11 1b 91 11 18 58 13 1e 11 1c 11 1d 61 13 1f 11 1f 11 1e 59 13 20 08 11 1a 11 20 11 18 5d d2 9c 00 11 17 17 58 13 17 11 17 20 00 ba 00 00 fe 04 13 21 11 21 2d 98 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Agenttesla_ARAJ_MTB_2{
	meta:
		description = "Trojan:BAT/Agenttesla.ARAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 07 91 0c 03 07 03 8e 69 5d 91 0d 16 13 04 16 13 05 2b 41 00 08 17 11 05 1f 1f 5f 62 5f 16 fe 03 13 06 09 17 11 05 1f 1f 5f 62 5f 16 fe 03 13 07 11 06 11 07 61 13 08 11 08 13 09 11 09 2c 0e 11 04 17 11 05 1f 1f 5f 62 d2 60 d2 13 04 00 11 05 17 58 13 05 11 05 1e fe 04 13 0a 11 0a 2d b4 06 07 11 04 9c 00 07 17 58 0b 07 02 8e 69 fe 04 13 0b 11 0b 2d 89 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}