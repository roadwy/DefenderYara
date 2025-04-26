
rule Trojan_BAT_AgentTesla_PSOA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSOA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 04 00 00 0a 73 03 04 00 06 28 04 04 00 06 75 01 00 00 1b 6f 05 00 00 0a 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}