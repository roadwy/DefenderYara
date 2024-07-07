
rule Trojan_BAT_AgentTesla_AND_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {91 08 61 06 11 04 91 61 d2 9c 11 04 03 90 01 05 17 59 fe 01 13 06 11 06 2c 05 16 13 04 2b 06 11 04 17 58 13 04 00 11 05 17 58 13 05 11 05 07 17 59 fe 02 16 fe 01 13 07 11 07 2d bb 90 00 } //10
		$a_03_1 = {13 07 11 07 2c 2c 00 06 12 06 90 01 0b 06 12 06 90 01 0b 06 12 06 90 01 0d 11 05 17 d6 13 05 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}