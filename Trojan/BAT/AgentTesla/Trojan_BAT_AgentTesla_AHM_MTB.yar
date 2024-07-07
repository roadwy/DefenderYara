
rule Trojan_BAT_AgentTesla_AHM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 1a 00 00 04 19 9a 1f 16 07 0c 95 7e 1a 00 00 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}