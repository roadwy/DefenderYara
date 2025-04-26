
rule Trojan_BAT_AgentTesla_AALM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AALM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 14 2b 19 00 11 06 11 14 11 06 11 14 91 20 ?? 04 00 00 59 d2 9c 00 11 14 17 58 13 14 11 14 11 06 8e 69 fe 04 13 15 11 15 2d d9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}