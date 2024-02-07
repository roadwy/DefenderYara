
rule Trojan_BAT_AgentTesla_ABEO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {02 28 7f 00 00 0a 28 90 01 03 0a 2a 90 00 } //02 00 
		$a_03_1 = {01 25 16 20 90 01 03 aa 28 90 01 03 06 a2 25 17 20 90 01 03 aa 28 90 01 03 06 a2 14 14 14 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 06 28 90 01 03 0a 0b 14 90 00 } //01 00 
		$a_01_2 = {45 78 63 65 72 65 73 74 69 6e 74 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Excerestint.Resources.resources
		$a_01_3 = {45 00 78 00 63 00 65 00 72 00 65 00 73 00 74 00 69 00 6e 00 74 00 } //00 00  Excerestint
	condition:
		any of ($a_*)
 
}