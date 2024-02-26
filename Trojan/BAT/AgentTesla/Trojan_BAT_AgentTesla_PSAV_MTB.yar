
rule Trojan_BAT_AgentTesla_PSAV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {7e 5f 01 00 04 25 13 26 12 17 28 6a 00 00 0a 73 6b 00 00 0a 0b d0 23 00 00 02 28 8f 01 00 06 6f 5a 00 00 0a 72 ac 35 00 70 6f 6c 00 00 0a 73 6d 00 00 0a 0c 08 28 8c 01 00 06 16 6a 28 8d 01 00 06 08 08 6f 6e 00 00 0a 6f 6f 00 00 0a 69 6f 70 00 00 0a 0d 08 28 90 01 00 06 09 8e 69 16 } //00 00 
	condition:
		any of ($a_*)
 
}