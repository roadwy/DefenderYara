
rule Trojan_BAT_AgentTesla_PGS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PGS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 00 20 07 00 00 00 38 ?? ff ff ff 11 02 11 03 11 00 11 03 91 11 04 11 03 11 04 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 20 06 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 ?? fe ff ff 26 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}