
rule Trojan_BAT_AgentTesla_PTGU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTGU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 06 1a 00 00 06 73 14 00 00 0a 28 02 00 00 2b 28 03 00 00 2b 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}