
rule Trojan_BAT_AgentTesla_PSOR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSOR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 38 2b 00 00 00 73 90 01 03 0a 0a dd 90 01 03 00 26 72 8b 1b 00 70 72 2a 1c 00 70 28 90 01 03 0a 6f 90 01 03 0a 74 71 00 00 01 0a dd 00 00 00 00 06 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}