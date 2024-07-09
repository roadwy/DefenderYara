
rule Trojan_BAT_AgentTesla_ASBA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 13 04 2b 23 00 06 11 04 18 6f ?? 00 00 0a 13 05 07 11 04 18 5b 11 05 1f 10 28 ?? 00 00 0a d2 9c 00 11 04 18 58 13 04 11 04 06 6f ?? 00 00 0a fe 04 13 06 11 06 2d cd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}