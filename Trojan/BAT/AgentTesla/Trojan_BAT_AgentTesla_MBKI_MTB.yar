
rule Trojan_BAT_AgentTesla_MBKI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 06 07 06 8e 69 5d 91 11 04 07 11 04 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 28 90 01 01 00 00 0a 06 07 17 58 06 8e 69 5d 91 28 90 01 01 00 00 0a 59 20 00 01 00 00 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}