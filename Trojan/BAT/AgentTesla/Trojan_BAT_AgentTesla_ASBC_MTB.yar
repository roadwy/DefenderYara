
rule Trojan_BAT_AgentTesla_ASBC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 13 05 2b 23 00 07 11 05 18 6f ?? 00 00 0a 13 06 08 11 05 18 5b 11 06 1f 10 28 ?? 00 00 0a d2 9c 00 11 05 18 58 13 05 11 05 07 6f ?? 00 00 0a fe 04 13 07 11 07 2d cd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}