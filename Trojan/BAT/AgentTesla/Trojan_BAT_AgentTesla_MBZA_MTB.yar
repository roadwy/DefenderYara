
rule Trojan_BAT_AgentTesla_MBZA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0a 17 6a 58 13 17 20 00 01 00 00 13 13 11 0b 11 12 11 0b 11 12 91 1f 16 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}