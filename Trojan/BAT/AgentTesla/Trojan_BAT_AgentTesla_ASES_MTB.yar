
rule Trojan_BAT_AgentTesla_ASES_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 11 0a 11 0f 20 00 01 00 00 5d d2 9c 00 11 09 17 59 13 09 11 } //01 00 
		$a_01_1 = {11 09 09 5d 13 0a 11 09 11 04 5d 13 0b 07 11 0a 91 13 0c 08 11 0b } //01 00 
		$a_01_2 = {13 0d 07 11 09 17 58 09 5d 91 13 0e } //01 00 
		$a_01_3 = {49 6e 74 65 72 56 69 65 77 43 6f 64 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  InterViewCode.Properties.Resources
	condition:
		any of ($a_*)
 
}