
rule Trojan_BAT_AgentTesla_MBCN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 11 06 08 11 06 91 07 11 06 07 8e 69 5d 91 61 d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_MBCN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 5f 00 35 00 41 00 5f 00 39 00 50 00 50 00 33 00 3f 00 50 00 50 00 50 00 34 00 3f 00 50 00 50 00 30 00 5f 00 46 00 46 00 5f 00 46 00 46 00 3f 00 50 00 30 00 5f 00 42 00 38 00 3f 00 } //01 00 
		$a_01_1 = {50 00 50 00 50 00 50 00 50 00 50 00 50 00 50 00 50 00 50 00 30 00 5f 00 38 00 50 00 50 00 50 00 50 00 45 00 5f 00 31 00 46 00 5f 00 42 00 41 00 3f 00 45 00 3f 00 30 00 5f 00 42 00 34 00 } //00 00 
	condition:
		any of ($a_*)
 
}