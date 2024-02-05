
rule Trojan_BAT_AgentTesla_SRP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0a 73 65 00 00 0a 0b 07 06 6f 66 00 00 0a 00 07 03 6f 67 00 00 0a 00 07 73 68 00 00 0a 0c 73 69 00 00 0a 0d 08 09 6f 6a 00 00 0a 26 09 13 04 2b 00 11 04 2a } //01 00 
		$a_01_1 = {68 58 78 65 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}