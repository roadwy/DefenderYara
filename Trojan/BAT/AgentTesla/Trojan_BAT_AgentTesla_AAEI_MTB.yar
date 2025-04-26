
rule Trojan_BAT_AgentTesla_AAEI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 08 2b 22 00 06 11 08 18 6f ?? 00 00 0a 13 09 07 11 08 18 5b 11 09 1f 10 28 ?? 00 00 0a 9c 00 11 08 18 58 13 08 11 08 06 6f ?? 00 00 0a fe 04 13 0a 11 0a 2d ce } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}