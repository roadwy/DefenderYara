
rule Trojan_BAT_AgentTesla_GAS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 16 13 05 2b 2d 09 11 05 06 11 05 91 08 61 07 11 04 91 61 28 ?? 00 00 0a 9c 2b 00 11 04 1f 15 33 05 16 13 04 2b 06 11 04 17 58 13 04 11 05 17 58 13 05 11 05 06 8e 69 17 59 31 ca } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}