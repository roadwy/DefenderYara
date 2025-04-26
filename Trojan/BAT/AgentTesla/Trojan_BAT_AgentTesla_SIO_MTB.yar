
rule Trojan_BAT_AgentTesla_SIO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SIO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 19 5d 16 fe 01 0c 08 2c 08 02 07 02 07 91 03 61 9c 07 17 d6 0b 07 06 31 e6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_SIO_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SIO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 08 11 08 61 11 07 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 09 07 09 11 09 d2 9c 09 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_SIO_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.SIO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 28 83 00 00 06 13 05 11 04 1f 16 5d 13 06 11 04 17 58 13 07 07 11 04 91 11 05 11 06 91 61 13 08 07 11 04 11 08 07 11 07 07 8e 69 5d 91 59 20 00 01 00 00 58 d2 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 09 11 09 2d b5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}