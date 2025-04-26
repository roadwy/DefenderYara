
rule Trojan_BAT_AgentTesla_GAR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 06 16 0a 16 0d 2b 29 06 08 5d 13 0a 06 08 5b 13 0b 07 11 0a 11 0b 6f ?? 00 00 0a 13 0c 11 05 09 12 0c 28 ?? 00 00 0a 9c 09 17 58 0d 06 17 58 0a 06 08 11 06 5a 32 d0 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}