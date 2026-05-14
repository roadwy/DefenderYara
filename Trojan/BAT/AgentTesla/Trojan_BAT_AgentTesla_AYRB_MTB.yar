
rule Trojan_BAT_AgentTesla_AYRB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AYRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 05 11 06 6f ?? 00 00 06 13 0d 12 0d 28 ?? 00 00 0a 13 0e 12 0d 28 ?? 00 00 0a 13 0f 02 11 0e 11 0f 6f ?? 00 00 0a 13 10 07 11 10 6f ?? 00 00 06 13 10 08 17 6f ?? 00 00 06 12 10 28 ?? 00 00 0a 13 09 11 09 28 ?? 00 00 06 28 ?? 00 00 06 13 09 11 09 18 62 11 09 1c 63 60 d2 13 09 11 09 18 63 11 09 1c 62 60 d2 13 09 11 04 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}