
rule Trojan_BAT_AgentTesla_PTJW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {d0 1a 00 00 04 28 ?? 00 00 0a 00 13 07 16 13 14 2b 1e 11 06 11 14 11 05 11 14 18 5a 18 6f 4c 00 00 0a 1f 10 28 ?? 00 00 0a 9c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}