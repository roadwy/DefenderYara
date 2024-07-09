
rule Trojan_BAT_AgentTesla_ASCH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 05 07 8e 69 5d 07 11 05 07 8e 69 5d 91 08 11 05 1f 16 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 07 11 05 17 58 07 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 00 00 0a 9c 00 11 05 15 58 13 05 11 05 16 fe 04 16 fe 01 13 06 11 06 2d a8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}