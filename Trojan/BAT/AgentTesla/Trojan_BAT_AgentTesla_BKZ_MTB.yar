
rule Trojan_BAT_AgentTesla_BKZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BKZ!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {03 50 09 03 50 8e 69 6a 5d b7 91 07 09 07 8e 69 6a 5d b7 91 61 03 50 09 17 6a d6 03 50 8e 69 6a 5d b7 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 } //00 00 
	condition:
		any of ($a_*)
 
}