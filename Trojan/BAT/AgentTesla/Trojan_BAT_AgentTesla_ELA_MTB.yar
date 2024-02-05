
rule Trojan_BAT_AgentTesla_ELA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ELA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 11 04 91 07 61 19 2c 3b 06 09 91 61 } //01 00 
		$a_01_1 = {8e 69 17 59 91 1f 70 61 } //00 00 
	condition:
		any of ($a_*)
 
}