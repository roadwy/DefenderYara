
rule Trojan_BAT_AgentTesla_EFE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {08 11 04 07 11 04 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 00 11 04 17 58 13 04 11 04 20 00 58 00 00 fe 04 90 00 } //0a 00 
		$a_03_1 = {07 09 06 09 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 00 09 17 58 0d 09 20 00 58 00 00 fe 04 90 00 } //01 00 
		$a_01_2 = {00 47 65 74 54 79 70 65 } //01 00 
		$a_01_3 = {00 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 00 } //01 00 
		$a_01_4 = {00 53 75 62 73 74 72 69 6e 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}