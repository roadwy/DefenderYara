
rule Trojan_BAT_AgentTesla_PSES_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 7e 05 00 00 04 28 90 01 03 0a 02 6f 90 01 03 0a 6f 90 01 03 0a 0a 2b 00 06 2a 90 00 } //02 00 
		$a_03_1 = {00 7e 04 00 00 04 6f 90 01 03 0a 02 16 02 8e 69 6f 90 01 03 0a 0a 2b 00 06 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}