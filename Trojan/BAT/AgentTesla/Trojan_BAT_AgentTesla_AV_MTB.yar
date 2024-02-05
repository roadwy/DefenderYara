
rule Trojan_BAT_AgentTesla_AV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 07 72 ff 01 00 70 72 6d 01 00 70 72 23 00 00 70 28 5a 00 00 0a 6f 90 01 04 0c 08 14 02 28 41 00 00 06 6f 90 01 04 26 2a 90 00 } //01 00 
		$a_00_1 = {67 65 74 5f 69 69 69 } //01 00 
		$a_00_2 = {42 00 20 00 75 00 20 00 74 00 20 00 61 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}