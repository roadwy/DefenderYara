
rule Trojan_BAT_AgentTesla_AMSA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 17 d2 13 2f 11 17 1e 63 d1 13 17 11 1e 11 09 91 13 21 11 1e 11 09 11 24 11 21 61 19 11 18 58 61 11 2f 61 d2 9c 17 11 09 58 13 09 11 21 13 18 11 09 11 26 32 a4 } //5
		$a_01_1 = {11 32 11 13 11 11 11 13 91 9d 17 11 13 58 13 13 11 13 11 1b 32 ea } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}