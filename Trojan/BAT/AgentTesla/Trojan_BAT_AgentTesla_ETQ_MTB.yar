
rule Trojan_BAT_AgentTesla_ETQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ETQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 03 17 58 90 01 05 5d 91 0a 16 0b 17 0c 00 02 03 28 5d 00 00 06 0d 06 04 58 13 04 09 11 04 59 04 5d 0b 00 02 03 90 01 05 5d 07 d2 9c 02 90 00 } //01 00 
		$a_03_1 = {5d 91 0a 06 90 01 05 03 1f 16 5d 90 01 05 61 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}