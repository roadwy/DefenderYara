
rule Trojan_BAT_AgentTesla_GAU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 16 13 05 16 13 06 2b 2f 11 05 09 5d 13 07 11 05 09 5b 13 08 08 11 07 11 08 6f ?? 00 00 0a 13 09 07 11 06 12 09 28 ?? 00 00 0a 9c 11 06 17 58 13 06 11 05 17 58 13 05 11 05 09 11 04 5a 32 c9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}