
rule Trojan_BAT_AgentTesla_AMAG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 06 11 0f 17 8d 90 01 01 00 00 01 25 16 11 05 11 0f 9a 1f 10 28 90 01 01 00 00 0a 86 9c 6f 90 01 01 00 00 0a 00 11 0f 17 d6 13 0f 11 0f 11 0e 31 d4 90 00 } //01 00 
		$a_01_1 = {4c 00 6f 00 2d 00 61 00 64 00 20 00 01 03 2d 00 01 11 44 00 65 00 6c 00 65 00 74 00 65 00 4d 00 43 } //00 00 
	condition:
		any of ($a_*)
 
}