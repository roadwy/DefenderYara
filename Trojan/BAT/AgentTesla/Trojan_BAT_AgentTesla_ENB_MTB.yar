
rule Trojan_BAT_AgentTesla_ENB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ENB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8e 65 51 d1 8e 67 d1 8e 46 59 d1 8e 5a 51 42 79 d1 8e 48 4d d1 8e 61 51 42 76 d1 8e 47 34 d1 8e d1 8e d1 8e d1 8e 78 d1 8e 43 34 d1 8e 4d d1 8e } //01 00 
		$a_01_1 = {8e 42 63 35 46 52 59 54 d1 8e 43 49 35 4d 78 59 54 d1 8e 43 30 35 53 52 59 54 d1 8e 44 67 35 59 52 59 54 d1 8e 45 4d 35 65 52 59 54 d1 8e 45 34 } //01 00 
		$a_01_2 = {42 69 5a 53 42 79 64 57 34 67 61 57 34 67 52 45 39 54 49 47 31 76 5a 47 55 75 44 51 30 4b 4a d1 8e d1 8e d1 8e d1 8e d1 8e d1 8e d1 8e d1 8e d1 } //00 00 
	condition:
		any of ($a_*)
 
}