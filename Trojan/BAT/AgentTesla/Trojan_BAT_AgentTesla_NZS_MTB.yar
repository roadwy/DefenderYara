
rule Trojan_BAT_AgentTesla_NZS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 44 27 35 41 27 39 30 3e 5d 27 30 33 3e 7d 7d 5d 27 30 34 3e 7d 7d 5d 27 46 46 27 46 46 3e 7d 5d 27 42 38 3e 7d 7d 7d 7d 7d 7d 5d 27 34 30 } //01 00 
		$a_01_1 = {30 3e 7d 7d 5d 27 45 32 3e 7d 7d 5d 27 30 32 3e 7d 7d 7d 7d 7d 7d 7d 7d 7d 7d 7d 7d 7d 5d 27 32 30 3e 7d 5d 27 36 30 27 32 45 27 37 32 27 37 } //00 00 
	condition:
		any of ($a_*)
 
}