
rule Trojan_BAT_AgentTesla_NZH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 52 0f 00 70 72 56 0f 00 70 6f 90 01 03 0a 17 8d 90 01 03 01 25 16 1f 26 9d 6f 90 01 03 0a 0a 73 90 01 03 0a 0b 16 13 08 2b 1d 07 06 11 08 9a 1f 10 28 90 01 03 0a 8c 90 01 03 01 6f 90 01 03 0a 26 11 08 17 58 13 08 90 00 } //01 00 
		$a_81_1 = {53 43 55 49 59 47 54 44 49 55 59 44 53 47 2e 72 } //00 00 
	condition:
		any of ($a_*)
 
}