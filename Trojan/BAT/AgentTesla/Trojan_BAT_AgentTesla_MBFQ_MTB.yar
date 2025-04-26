
rule Trojan_BAT_AgentTesla_MBFQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 35 00 41 00 39 00 7b 00 7d 00 7b 00 7d 00 33 00 7b 00 7d 00 7b 00 7d 00 7b 00 7d 00 30 00 34 00 7b 00 7d 00 7b 00 7d 00 7b 00 7d 00 46 00 46 00 46 00 46 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}