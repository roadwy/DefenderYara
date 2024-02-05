
rule Trojan_BAT_AgentTesla_GAX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {14 0a 38 26 00 00 00 00 28 90 01 01 00 00 0a 72 90 01 01 00 00 70 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0a dd 06 00 00 00 26 dd 00 00 00 00 06 2c d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}