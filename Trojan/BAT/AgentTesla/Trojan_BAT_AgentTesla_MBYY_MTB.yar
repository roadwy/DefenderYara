
rule Trojan_BAT_AgentTesla_MBYY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 16 5d 91 13 [0-15] 61 [0-09] 17 58 [0-07] 5d [0-22] 20 00 01 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}