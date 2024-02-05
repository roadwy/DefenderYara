
rule Trojan_BAT_AgentTesla_DFE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 04 7e 90 01 03 04 02 11 04 91 07 61 06 09 91 61 28 90 01 03 06 9c 09 7e 90 01 03 04 03 28 90 01 03 06 17 59 16 90 00 } //01 00 
		$a_01_1 = {00 66 67 68 00 70 72 6f 6a 44 61 74 61 00 4b 31 00 78 79 7a 00 } //01 00 
		$a_01_2 = {00 75 67 7a 31 00 75 67 7a 33 00 70 72 6f 6a 6e 61 6d 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}