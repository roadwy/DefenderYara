
rule Trojan_BAT_AgentTesla_PSZO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSZO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {61 2b c7 28 90 01 01 00 00 06 0b 02 07 06 28 90 01 01 00 00 06 74 03 00 00 1b 7d 44 00 00 04 06 28 90 01 01 00 00 06 08 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}