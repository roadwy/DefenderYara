
rule Trojan_BAT_AgentTesla_ASGD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 09 5d 13 05 06 17 58 13 0b 08 11 05 91 13 0c 08 11 05 11 0c 11 06 06 1f 16 5d 91 61 08 11 0b 09 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 06 17 58 0a 06 09 11 07 17 58 5a 32 } //00 00 
	condition:
		any of ($a_*)
 
}