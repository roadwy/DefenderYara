
rule Trojan_BAT_AgentTesla_ABYD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABYD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 09 5d 13 0a 11 05 09 5b 13 0b 08 11 0a 11 0b 6f 90 01 01 00 00 0a 13 0c 07 11 06 12 0c 28 90 01 01 00 00 0a 9c 11 06 17 58 13 06 11 05 17 58 13 05 11 05 09 11 04 5a 32 c9 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}