
rule Trojan_BAT_AgentTesla_MBCO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 08 02 8e 69 5d 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 01 00 00 0a 02 08 1d 58 1c 59 02 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}