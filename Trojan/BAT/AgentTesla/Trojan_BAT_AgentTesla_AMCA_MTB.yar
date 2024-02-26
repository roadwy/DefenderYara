
rule Trojan_BAT_AgentTesla_AMCA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {13 0a 07 11 0a 91 11 07 58 13 0b 07 11 09 91 13 0c 11 0c 08 11 06 1f 16 5d 91 61 13 0d 11 0d 11 0b 59 13 0e 07 11 09 11 0e 11 07 5d d2 9c 00 11 06 17 58 13 06 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AMCA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AMCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {13 0b 08 11 0b 91 11 08 58 13 0c 08 11 0a 91 13 0d 09 11 04 1f 16 5d 91 13 0e 11 0d 11 0e 61 13 0f 11 0f 11 0c 59 13 10 08 11 0a 11 10 11 08 5d d2 9c 11 04 17 58 13 04 } //00 00 
	condition:
		any of ($a_*)
 
}