
rule Trojan_BAT_AgentTesla_PTIM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 95 11 9d 67 18 28 ?? 00 00 06 12 12 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 11 12 28 ?? 00 00 06 a2 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}