
rule Trojan_BAT_AgentTesla_NZU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {08 06 8e 69 5d 06 08 06 8e 69 5d 91 07 08 1f 16 5d 91 61 28 90 01 03 0a 06 08 17 58 06 8e 69 5d 91 28 90 01 03 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 90 00 } //01 00 
		$a_81_1 = {43 38 41 45 44 48 41 55 56 48 37 35 49 34 37 52 52 37 52 44 35 48 } //01 00 
		$a_81_2 = {4a 45 50 34 35 57 4a 38 45 39 5a 37 48 37 37 35 34 38 37 4a 51 38 } //00 00 
	condition:
		any of ($a_*)
 
}