
rule Trojan_BAT_AgentTesla_NTV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 05 04 5d 91 03 05 1f 16 5d 6f 90 01 03 0a 61 0a 06 2a 90 00 } //01 00 
		$a_03_1 = {20 00 01 00 00 0a 03 02 20 00 7a 00 00 04 28 90 01 03 06 03 04 17 58 20 00 7a 00 00 5d 91 59 06 58 06 5d 0b 03 04 20 00 7a 00 00 5d 07 d2 9c 03 0c 08 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}