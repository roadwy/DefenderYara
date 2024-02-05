
rule Trojan_BAT_AgentTesla_ASEG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 07 11 06 28 90 01 01 00 00 06 13 0b 02 11 09 11 0a 11 0b 28 90 01 01 00 00 06 13 0c 07 11 07 11 0c 20 00 01 00 00 5d d2 9c 11 10 20 90 02 04 5a 20 90 02 04 61 38 90 00 } //01 00 
		$a_01_1 = {11 06 07 8e 69 5d 13 07 20 } //00 00 
	condition:
		any of ($a_*)
 
}