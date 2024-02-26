
rule Trojan_BAT_AgentTesla_SPQE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPQE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {20 00 01 00 00 0d 06 17 58 13 09 06 20 00 0e 01 00 5d 13 04 11 09 20 00 0e 01 00 5d 13 0a 07 11 0a 91 09 58 13 0b 07 11 04 91 13 0c 11 06 06 1f 16 5d 91 13 0d 11 0c 11 0d 61 13 0e 11 0e 11 0b 59 13 0f 07 11 04 11 0f 09 5d d2 9c 06 17 58 0a } //00 00 
	condition:
		any of ($a_*)
 
}