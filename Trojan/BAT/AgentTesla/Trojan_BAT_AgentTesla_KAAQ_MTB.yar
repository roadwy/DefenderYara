
rule Trojan_BAT_AgentTesla_KAAQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KAAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 1a 09 5d 13 1b 11 1a 11 04 5d 13 1c 07 11 1b 91 13 1d 08 11 1c 6f 90 01 01 00 00 0a 13 1e 02 07 11 1a 28 90 01 01 00 00 06 13 1f 02 11 1d 11 1e 11 1f 28 90 01 01 00 00 06 13 20 07 11 1b 11 20 20 90 01 02 00 00 5d d2 9c 00 11 1a 17 59 13 1a 11 1a 16 fe 04 16 fe 01 13 21 11 21 2d a7 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}