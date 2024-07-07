
rule Trojan_BAT_AgentTesla_PTGS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTGS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff ff 11 00 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 28 90 01 04 02 7b 04 00 00 04 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}