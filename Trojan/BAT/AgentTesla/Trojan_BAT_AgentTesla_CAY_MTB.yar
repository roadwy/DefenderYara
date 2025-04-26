
rule Trojan_BAT_AgentTesla_CAY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAY!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 03 05 03 8e 69 5d 91 05 04 03 8e 69 5d d6 04 5f 61 b4 61 10 00 02 0a 2b 00 06 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}