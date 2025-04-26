
rule Trojan_BAT_AgentTesla_ABMP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 07 09 07 9a 1f 10 28 ?? 00 00 0a 9c 07 17 58 0b 07 09 8e 69 fe 04 13 07 11 07 2d e2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}