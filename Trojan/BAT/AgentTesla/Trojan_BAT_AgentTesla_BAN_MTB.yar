
rule Trojan_BAT_AgentTesla_BAN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {70 18 18 8d 90 01 03 01 25 16 09 8c 90 01 03 01 a2 25 17 11 04 8c 90 01 03 01 a2 28 90 01 03 0a 25 2d 0d 26 12 0a 90 01 06 11 0a 2b 05 90 01 05 28 90 01 03 0a 13 09 07 06 11 09 b4 9c 11 04 17 d6 13 04 11 04 11 08 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_BAN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {2c 05 11 3d 16 35 03 16 2b 01 17 17 59 11 39 20 e7 02 00 00 95 5f 11 39 20 43 06 00 00 95 61 58 13 2e } //02 00 
		$a_01_1 = {11 1c 33 0b 11 3a 13 3a 16 11 16 13 21 2b 01 17 17 59 11 1b 20 52 09 00 00 95 5f 11 1b 20 0b 0d 00 00 95 61 58 13 19 } //00 00 
	condition:
		any of ($a_*)
 
}