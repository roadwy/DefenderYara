
rule Trojan_BAT_AgentTesla_GAZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 16 13 06 2b 2e 00 11 06 09 5d 13 07 11 06 09 5b 13 08 08 11 07 11 08 6f 90 01 01 00 00 0a 13 09 07 12 09 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 00 11 06 17 58 13 06 11 06 09 11 04 5a fe 04 13 0a 11 0a 2d c4 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}