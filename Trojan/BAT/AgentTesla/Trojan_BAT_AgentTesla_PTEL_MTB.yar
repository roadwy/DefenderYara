
rule Trojan_BAT_AgentTesla_PTEL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {39 b6 00 00 00 28 90 01 01 00 00 06 6c 28 90 01 01 00 00 06 06 28 90 01 01 00 00 06 28 90 01 01 00 00 06 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}