
rule Trojan_BAT_AgentTesla_NUU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NUU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 03 20 00 7e 00 00 5d 91 0a 06 7e } //01 00 
		$a_01_1 = {06 03 04 17 58 20 00 7e 00 00 5d 91 59 05 58 05 5d 0a 03 04 20 00 7e 00 00 5d 06 d2 9c 03 0b 07 2a } //00 00 
	condition:
		any of ($a_*)
 
}