
rule Trojan_BAT_AgentTesla_EFF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 28 90 01 03 0a 20 9e 02 00 00 da 13 05 11 05 28 90 01 03 0a 28 90 01 03 0a 13 06 07 11 06 28 90 01 03 0a 0b 00 09 17 d6 0d 90 09 0c 00 08 09 6f 90 01 03 0a 28 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {42 00 75 00 7e 00 7e 00 6e 00 7e 00 7e 00 69 00 66 00 7e 00 7e 00 75 00 5f 00 7e 00 7e 00 54 00 65 00 7e 00 7e 00 78 00 74 00 7e 00 7e 00 42 00 6f 00 7e 00 7e 00 78 00 } //01 00 
		$a_01_2 = {78 00 6f 00 42 00 74 00 78 00 65 00 54 00 5f 00 75 00 66 00 69 00 6e 00 75 00 42 00 } //00 00 
	condition:
		any of ($a_*)
 
}