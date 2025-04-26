
rule Trojan_BAT_AgentTesla_PTHR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 8f 00 00 70 28 ?? 00 00 0a 06 28 ?? 00 00 0a 0b 02 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}