
rule Trojan_BAT_AgentTesla_MBIE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBIE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 09 07 09 91 06 09 06 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 d2 9c 09 17 58 0d 09 07 8e 69 32 90 00 } //01 00 
		$a_03_1 = {20 76 83 00 00 28 90 01 01 00 00 06 0a 14 0b 28 90 01 01 00 00 06 0b 07 8e 69 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}