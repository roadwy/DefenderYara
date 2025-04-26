
rule Trojan_BAT_AgentTesla_AAUN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAUN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 18 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 07 72 c3 04 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 0c 08 06 16 06 8e 69 6f ?? 00 00 0a 0d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}