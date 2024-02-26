
rule Trojan_BAT_AgentTesla_ASFQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 07 06 8e 69 5d 02 06 07 06 8e 69 5d 91 11 04 07 11 04 6f } //01 00 
		$a_03_1 = {0a 06 07 17 58 06 8e 69 5d 91 28 90 01 02 00 0a 59 20 00 01 00 00 58 28 90 01 01 00 00 06 28 90 01 02 00 0a 9c 07 15 58 0b 07 16 fe 04 16 fe 01 13 07 11 07 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}