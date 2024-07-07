
rule Trojan_BAT_AgentTesla_ABZI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABZI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 90 01 01 00 00 0a 02 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0c 06 08 6f 90 01 01 00 00 0a 00 06 18 6f 90 01 01 00 00 0a 00 06 6f 90 01 01 00 00 0a 7e 90 01 02 00 04 16 7e 90 01 02 00 04 8e 69 6f 90 01 01 00 00 0a 0d 2b 00 09 2a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}