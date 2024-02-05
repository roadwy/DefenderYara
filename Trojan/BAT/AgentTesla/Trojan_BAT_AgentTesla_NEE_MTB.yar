
rule Trojan_BAT_AgentTesla_NEE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {da 17 d6 8d 15 00 00 01 13 05 02 02 8e b7 17 da 91 0a 28 90 01 01 00 00 0a 72 90 01 01 00 00 70 6f 90 01 01 00 00 0a 0c 12 05 90 00 } //01 00 
		$a_01_1 = {41 44 49 6e 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NEE_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 07 00 00 05 00 "
		
	strings :
		$a_01_0 = {4d 4a 43 4b 56 4b 4c 55 49 4f 52 } //05 00 
		$a_01_1 = {4e 4d 43 58 4e 43 4e 4d 58 43 4e 58 43 4d 46 44 4b 4c 46 44 46 44 4b 4c 46 } //05 00 
		$a_01_2 = {43 58 43 43 58 48 4a 43 58 43 59 55 58 59 55 } //05 00 
		$a_01_3 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20 31 2e 36 2e 30 } //05 00 
		$a_01_4 = {76 34 2e 30 2e 33 30 33 31 39 } //01 00 
		$a_01_5 = {26 00 47 00 52 00 41 00 50 00 48 00 49 00 43 00 52 00 41 00 54 00 49 00 4e 00 47 00 2d 00 4b 00 4f 00 4c 00 4f 00 52 00 49 00 41 00 } //01 00 
		$a_01_6 = {2b 25 26 6f 41 } //00 00 
	condition:
		any of ($a_*)
 
}