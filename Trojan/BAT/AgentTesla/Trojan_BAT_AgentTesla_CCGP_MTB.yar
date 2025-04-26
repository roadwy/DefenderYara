
rule Trojan_BAT_AgentTesla_CCGP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CCGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 16 1f 16 5d 91 13 1c 07 11 1a 91 11 17 58 13 1d 11 1b 11 1c 61 13 1e 11 1e 11 1d 59 13 1f 07 11 19 11 1f 11 17 5d d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}