
rule Trojan_BAT_AgentTesla_ASAF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 07 8e 69 17 da 0d 16 13 04 38 90 01 01 00 00 00 08 07 11 04 9a 1f 10 7e 90 01 01 01 00 04 28 90 01 01 02 00 06 6f 90 01 01 00 00 0a 11 04 17 d6 13 04 11 04 09 3e 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}