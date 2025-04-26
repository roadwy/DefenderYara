
rule Trojan_BAT_AgentTesla_PSXA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 06 8e 69 2e 13 07 8d 06 00 00 01 0d 06 16 09 16 07 28 50 00 00 0a 09 0a 06 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}