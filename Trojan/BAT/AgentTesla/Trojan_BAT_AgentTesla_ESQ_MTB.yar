
rule Trojan_BAT_AgentTesla_ESQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ESQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 0a 03 02 90 01 05 04 90 01 05 03 04 17 58 90 01 05 5d 91 90 01 05 59 06 58 06 5d 0b 03 04 90 01 05 5d 07 d2 9c 03 0c 90 00 } //01 00 
		$a_03_1 = {02 05 04 5d 91 0a 06 03 05 1f 16 5d 90 01 05 61 0b 2b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}