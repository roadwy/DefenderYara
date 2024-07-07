
rule Trojan_BAT_AgentTesla_PSXO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSXO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 28 00 00 0a 20 00 00 00 00 3e 3b 00 00 00 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 fe 0c 01 00 6f 27 00 00 0a 28 90 01 01 00 00 0a 6f 1a 00 00 0a 20 39 7c 19 14 28 90 01 01 02 00 06 28 90 01 01 00 00 06 20 2f 7c 19 14 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}