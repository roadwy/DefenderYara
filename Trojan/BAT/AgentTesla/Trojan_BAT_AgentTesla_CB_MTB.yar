
rule Trojan_BAT_AgentTesla_CB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 01 00 00 0c 00 "
		
	strings :
		$a_02_0 = {0a 00 07 28 90 01 04 03 6f 90 01 04 6f 90 01 04 13 06 08 11 06 6f 90 01 04 00 08 18 6f 90 01 04 00 08 6f 90 01 04 13 05 02 28 90 01 04 13 04 28 90 01 04 11 05 11 04 16 11 04 8e b7 6f 90 01 04 6f 90 01 04 0a 06 0d de 13 de 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_CB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 d0 90 01 03 02 28 90 01 03 0a 6f 90 01 03 0a 73 1c 00 00 90 00 } //01 00 
		$a_01_1 = {59 00 41 00 53 00 41 00 54 00 } //01 00  YASAT
		$a_01_2 = {59 00 41 00 53 00 41 00 54 00 5f 00 52 00 65 00 70 00 6f 00 72 00 74 00 } //01 00  YASAT_Report
		$a_01_3 = {4f 00 6b 00 6c 00 61 00 68 00 6f 00 6d 00 61 00 20 00 54 00 69 00 72 00 65 00 20 00 26 00 20 00 53 00 75 00 70 00 70 00 6c 00 79 00 20 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 } //00 00  Oklahoma Tire & Supply Company
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_CB_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 6f 00 6e 00 77 00 61 00 79 00 4c 00 69 00 66 00 65 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  ConwayLife.Properties.Resources
		$a_01_1 = {73 00 65 00 20 00 73 00 69 00 6b 00 65 00 72 00 74 00 65 00 6c 00 65 00 6e 00 21 00 } //01 00  se sikertelen!
		$a_01_2 = {48 00 69 00 62 00 61 00 21 00 } //01 00  Hiba!
		$a_01_3 = {73 00 65 00 6c 00 66 00 69 00 65 00 5f 00 6d 00 65 00 } //01 00  selfie_me
		$a_01_4 = {73 00 65 00 6c 00 66 00 69 00 65 00 5f 00 70 00 61 00 6e 00 74 00 79 00 } //00 00  selfie_panty
	condition:
		any of ($a_*)
 
}