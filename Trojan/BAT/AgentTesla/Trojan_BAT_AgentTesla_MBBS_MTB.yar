
rule Trojan_BAT_AgentTesla_MBBS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 2d 00 35 00 41 00 2d 00 39 00 30 00 2d 00 7d 00 30 00 33 00 2d 00 7d 00 7d 00 7d 00 30 00 34 00 2d 00 7d 00 7d 00 7d 00 46 00 46 00 2d 00 46 00 46 00 2d 00 7d 00 7d 00 42 00 38 00 2d 00 7d 00 7d 00 7d 00 7d 00 7d 00 7d 00 7d 00 34 00 30 00 } //01 00 
		$a_01_1 = {7d 00 7d 00 34 00 38 00 2d 00 7d 00 7d 00 7d 00 7d 00 7d 00 7d 00 7d 00 7d 00 7d 00 7d 00 7d 00 32 00 45 00 2d 00 37 00 34 00 2d 00 36 00 35 00 2d 00 37 00 38 00 2d 00 37 00 34 00 2d 00 7d 00 7d 00 7d 00 30 00 } //00 00 
	condition:
		any of ($a_*)
 
}