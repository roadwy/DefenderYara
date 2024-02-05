
rule Trojan_BAT_AgentTesla_ESW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ESW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 0a 03 04 90 01 05 03 04 17 58 90 01 05 5d 91 90 01 05 59 06 58 06 5d 0b 03 04 90 01 05 5d 07 d2 9c 03 0c 2b 00 90 00 } //01 00 
		$a_03_1 = {91 0b 07 06 03 1f 16 5d 6f 90 01 03 0a 61 0c 2b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}