
rule Trojan_BAT_AgentTesla_AMAR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 07 08 8e 69 5d 13 08 11 07 09 6f ?? 00 00 0a 5d 13 09 08 11 08 91 13 0a 09 11 09 6f ?? 00 00 0a 13 0b 02 08 11 07 28 ?? 00 00 06 13 0c 02 11 0a 11 0b 11 0c 28 ?? 00 00 06 13 0d 08 11 08 02 11 0d 28 ?? 00 00 06 9c 00 11 07 17 59 13 07 11 07 16 fe 04 16 fe 01 13 0e 11 0e 2d a2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}