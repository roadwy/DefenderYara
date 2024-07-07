
rule Trojan_BAT_AgentTesla_AASN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AASN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 07 8e 69 5d 13 16 11 04 08 6f 90 01 01 00 00 0a 5d 13 17 07 11 16 91 13 18 08 11 17 6f 90 01 01 00 00 0a 13 19 02 07 11 04 28 90 01 01 00 00 06 13 1a 02 11 18 11 19 11 1a 28 90 01 01 00 00 06 13 1b 07 11 16 02 11 1b 28 90 01 01 00 00 06 9c 11 04 17 59 13 04 00 11 04 16 fe 04 16 fe 01 13 1c 11 1c 2d a2 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}