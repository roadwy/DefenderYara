
rule Trojan_BAT_AgentTesla_ABTP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABTP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 09 16 20 00 10 00 00 6f ?? 00 00 0a 13 05 11 05 16 fe 02 13 06 11 06 2c 0e 00 11 04 09 16 11 05 6f ?? 00 00 0a 00 00 00 11 05 16 fe 02 13 07 11 07 2d cb 72 8f 02 00 70 28 ?? 00 00 0a 72 c5 02 00 70 20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16 11 04 6f ?? 00 00 0a a2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}