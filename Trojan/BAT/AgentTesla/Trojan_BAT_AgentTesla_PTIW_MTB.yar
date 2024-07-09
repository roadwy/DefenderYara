
rule Trojan_BAT_AgentTesla_PTIW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTIW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 1b 00 00 04 11 00 6f 59 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 0a 20 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}