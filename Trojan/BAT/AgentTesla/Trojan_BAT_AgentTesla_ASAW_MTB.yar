
rule Trojan_BAT_AgentTesla_ASAW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 6f 90 01 01 00 00 0a 0c 08 2c 24 00 07 6f 90 01 01 00 00 0a 17 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 0d 2b 04 14 0d 2b 00 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}