
rule Trojan_BAT_AgentTesla_BU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 18 74 93 00 00 01 11 0b 74 29 00 00 1b 16 11 0b 75 29 00 00 1b 8e 69 6f 49 01 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}