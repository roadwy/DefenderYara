
rule Trojan_BAT_AgentTesla_AMAV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 18 6f 90 01 01 01 00 0a 00 06 18 6f 90 01 01 01 00 0a 00 06 72 90 01 03 70 28 90 01 01 01 00 0a 6f 90 01 01 01 00 0a 00 06 6f 90 01 01 01 00 0a 0b 28 90 01 01 00 00 06 0c 07 08 16 08 8e 69 6f 90 01 01 01 00 0a 0d 28 90 01 01 01 00 0a 09 6f 90 01 01 01 00 0a 13 04 11 04 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}