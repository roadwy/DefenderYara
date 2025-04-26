
rule Trojan_BAT_AgentTesla_MBDA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 16 0b 2b 2a 09 6f ?? 00 00 0a 07 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 28 ?? 00 00 0a 16 91 13 08 11 05 11 08 6f ?? 00 00 0a 07 18 58 0b 07 09 6f ?? 00 00 0a 6f ?? 00 00 0a fe 04 13 09 11 09 2d c2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}