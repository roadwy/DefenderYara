
rule Trojan_BAT_AgentTesla_AALC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AALC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 08 8e 69 5d 91 09 11 04 09 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 08 11 04 17 58 08 8e 69 5d 91 59 20 00 01 00 00 58 13 08 08 11 04 08 8e 69 5d 11 08 20 00 01 00 00 5d d2 9c 11 04 15 58 13 04 00 11 04 16 fe 04 16 fe 01 13 09 11 09 2d ae } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}