
rule Trojan_BAT_AgentTesla_ASDP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 08 8e 69 17 da 13 08 16 13 09 2b 23 09 11 09 17 8d 90 01 01 00 00 01 25 16 08 11 09 9a 1f 10 28 90 01 01 00 00 0a 86 9c 6f 90 01 01 00 00 0a 11 09 17 d6 13 09 11 09 11 08 31 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_ASDP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ASDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 04 5d 13 0a 11 09 11 05 5d 13 0b 08 11 0a 91 13 0c 09 11 0b 6f 90 01 01 00 00 0a 13 0d 08 11 09 17 58 11 04 5d 91 13 0e 11 0c 11 0d 61 11 0e 59 20 00 01 00 00 58 13 0f 08 11 0a 11 0f 20 00 01 00 00 5d d2 9c 00 11 09 17 59 13 09 11 09 16 fe 04 16 fe 01 13 10 11 10 2d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}