
rule Trojan_BAT_AgentTesla_MVE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 06 11 07 11 06 11 07 6f 3a 00 00 0a 06 11 05 06 8e 69 5d 91 61 d2 6f 3b 00 00 0a } //00 00 
	condition:
		any of ($a_*)
 
}