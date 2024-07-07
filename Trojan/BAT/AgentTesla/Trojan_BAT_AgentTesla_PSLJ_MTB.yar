
rule Trojan_BAT_AgentTesla_PSLJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSLJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 01 00 00 04 02 19 58 91 1f 18 62 60 0c 28 16 00 00 0a 7e 01 00 00 04 02 1a 58 08 6f 17 00 00 0a 28 18 00 00 0a a5 01 00 00 1b 0b 38 d6 00 00 00 06 18 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}