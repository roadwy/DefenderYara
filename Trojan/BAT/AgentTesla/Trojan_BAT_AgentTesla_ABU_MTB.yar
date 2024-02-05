
rule Trojan_BAT_AgentTesla_ABU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {95 2e 03 16 2b 01 17 17 59 7e 2e 00 00 04 17 9a 20 ae 02 00 00 95 5f 7e 2e 00 00 04 17 9a 20 08 02 00 00 95 61 58 81 0c 00 00 01 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ABU_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {1b 9a 20 9f 0c 00 00 95 6e 31 03 16 2b 01 17 7e 1e 00 00 04 1b 9a 20 e8 0a 00 00 95 5a 7e 1e 00 00 04 1b 9a 20 a0 04 00 00 95 58 61 81 05 00 00 01 } //00 00 
	condition:
		any of ($a_*)
 
}