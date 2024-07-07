
rule Trojan_BAT_AgentTesla_PSQS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSQS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 7e 0e 00 00 04 72 23 05 00 70 72 2f 05 00 70 72 39 05 00 70 28 1c 00 00 06 6f 34 00 00 0a 0a 2b 00 06 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}