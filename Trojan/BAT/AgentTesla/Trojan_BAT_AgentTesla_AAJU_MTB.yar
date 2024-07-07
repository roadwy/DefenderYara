
rule Trojan_BAT_AgentTesla_AAJU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 07 8e 69 5d 13 06 07 11 06 91 13 07 08 11 05 1f 16 5d 6f 90 01 01 00 00 0a d2 13 08 07 11 05 17 58 07 8e 69 5d 91 13 09 11 07 11 08 61 11 09 20 00 01 00 00 58 20 00 01 00 00 5d 59 13 0a 07 11 06 11 0a d2 9c 00 11 05 17 59 13 05 11 05 16 fe 04 16 fe 01 13 0b 11 0b 2d a5 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}