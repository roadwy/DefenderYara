
rule Trojan_BAT_AgentTesla_BAU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {09 94 13 07 11 09 09 11 09 11 05 94 9e 11 09 11 05 11 07 9e 11 09 11 09 09 94 11 09 11 05 94 58 20 00 01 00 00 5d 94 13 06 11 0a 11 04 07 11 04 91 11 06 61 d2 9c 11 04 13 0b 11 0b 17 58 13 04 11 04 07 8e 69 32 } //01 00 
		$a_01_1 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}