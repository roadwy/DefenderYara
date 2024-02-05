
rule Trojan_BAT_AgentTesla_AQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {00 02 07 8f 10 00 00 01 25 71 10 00 00 01 06 07 00 23 90 02 30 40 23 90 02 30 40 28 90 01 03 0a 58 28 90 01 03 0a 5d 91 61 d2 81 90 01 03 01 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d ba 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AQ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {1b 9a 20 9f 0f 00 00 95 e0 95 7e 2a 00 00 04 1b 9a 20 64 03 00 00 95 61 7e 2a 00 00 04 1b 9a 20 f8 09 00 00 95 2e 03 17 2b 01 16 58 } //02 00 
		$a_01_1 = {1b 9a 20 af 0f 00 00 95 5f 7e 2a 00 00 04 1b 9a 20 86 08 00 00 95 61 61 81 05 00 00 01 7e 2a 00 00 04 19 9a 1f 2f 95 7e 2a 00 00 04 1b 9a 20 39 05 00 00 95 33 6c } //00 00 
	condition:
		any of ($a_*)
 
}