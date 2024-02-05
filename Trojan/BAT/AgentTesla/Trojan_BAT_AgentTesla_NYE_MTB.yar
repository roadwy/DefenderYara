
rule Trojan_BAT_AgentTesla_NYE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NYE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 00 01 00 00 13 00 38 00 00 00 00 03 04 28 1f 00 00 06 03 04 17 58 20 00 3a 00 00 5d 91 59 11 00 58 11 00 5d 13 } //01 00 
		$a_01_1 = {24 38 65 32 31 66 37 36 66 2d 64 32 61 30 2d 34 38 32 66 2d 39 32 66 32 2d 35 66 34 36 38 34 64 31 36 39 65 33 } //00 00 
	condition:
		any of ($a_*)
 
}