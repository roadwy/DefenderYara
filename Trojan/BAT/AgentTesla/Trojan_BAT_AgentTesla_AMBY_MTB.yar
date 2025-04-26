
rule Trojan_BAT_AgentTesla_AMBY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0a 11 04 5d 13 0c 07 11 0c 91 11 09 58 13 0d 07 11 0b 91 13 0e 11 0e 08 11 08 1f 16 5d 91 61 13 0f 11 0f 11 0d 59 13 10 07 11 0b 11 10 11 09 5d d2 9c 00 11 08 17 58 13 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}