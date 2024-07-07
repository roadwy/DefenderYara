
rule Trojan_BAT_AgentTesla_NFQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 2a 8f 07 00 00 01 25 71 07 00 00 01 7e 2e 00 00 04 20 33 04 00 00 95 61 81 07 00 00 01 7e 2e 00 00 04 2c 08 7e 2e 00 00 04 8e 69 0a 7e 31 00 00 04 17 9a 1f 2a 95 7e 2e 00 00 04 20 64 03 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}