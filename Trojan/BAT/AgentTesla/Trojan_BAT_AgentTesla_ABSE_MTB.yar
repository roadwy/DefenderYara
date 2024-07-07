
rule Trojan_BAT_AgentTesla_ABSE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 07 11 05 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 00 11 05 18 58 13 05 11 05 07 6f 90 01 01 00 00 0a fe 04 13 06 11 06 2d d1 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}