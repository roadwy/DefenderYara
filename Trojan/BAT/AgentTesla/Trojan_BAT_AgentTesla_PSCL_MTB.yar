
rule Trojan_BAT_AgentTesla_PSCL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 28 0f 00 00 0a 0b 28 04 00 00 06 28 05 00 00 06 3a d0 00 00 00 26 20 0a 00 00 00 38 a0 ff ff ff 11 05 08 6f 10 00 00 0a 09 20 00 01 00 00 14 14 11 06 74 01 00 00 1b 6f 11 00 00 0a 26 20 0b 00 00 00 28 04 00 00 06 3a 74 ff ff ff 26 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}