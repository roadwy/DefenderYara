
rule Trojan_BAT_AgentTesla_QY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.QY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {91 06 07 06 8e 69 6a 5d 28 90 02 09 91 61 28 90 02 04 02 07 17 6a 58 02 8e 69 6a 5d 28 90 02 1b 5e d2 9c 00 07 17 6a 58 0b 07 02 8e 69 17 59 6a 03 17 58 6e 5a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}