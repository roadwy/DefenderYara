
rule Trojan_BAT_AgentTesla_FLA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 06 02 8e 69 6a 5d d4 02 06 02 8e 69 6a 5d d4 91 03 06 03 8e 69 6a 5d d4 91 61 02 06 17 6a 58 02 8e 69 6a 5d d4 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}