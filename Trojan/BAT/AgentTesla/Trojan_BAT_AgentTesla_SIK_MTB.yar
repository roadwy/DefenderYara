
rule Trojan_BAT_AgentTesla_SIK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {1f 16 13 04 20 00 01 00 00 13 05 09 20 00 56 00 00 5d 13 06 07 11 06 91 08 09 11 04 5d 6f 90 01 03 0a 61 28 90 01 03 0a 13 07 07 09 19 58 18 59 20 00 56 00 00 5d 91 28 90 01 03 0a 13 08 11 07 11 08 59 6e 11 05 6a 58 13 09 07 11 06 11 09 11 05 6a 5d 1f 19 6a 58 1f 19 6a 59 d2 9c 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 0a 11 0a 90 00 } //01 00 
		$a_81_1 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_81_2 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_3 = {48 00 65 00 61 00 76 00 79 00 44 00 75 00 63 00 6b 00 } //01 00  HeavyDuck
		$a_01_4 = {37 00 39 00 35 00 48 00 43 00 38 00 43 00 4a 00 31 00 51 00 46 00 31 00 42 00 54 00 32 00 34 00 48 00 47 00 57 00 48 00 35 00 35 00 } //00 00  795HC8CJ1QF1BT24HGWH55
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_SIK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SIK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 07 11 0c 17 6a 58 11 08 6a 5d d4 91 13 0d 11 0d 13 0e 07 11 0c 11 08 6a 5d d4 91 13 0f 08 11 0c 69 1f 16 5d 6f 28 00 00 0a 13 10 11 0f 11 10 61 13 11 11 11 11 0e 59 13 12 11 12 20 00 01 00 00 58 20 ff 00 00 00 5f 13 12 07 11 0c 11 08 6a 5d d4 11 12 28 29 00 00 0a 9c 00 11 0c 17 6a 58 13 0c 11 0c 11 08 17 59 6a fe 02 16 fe 01 13 13 11 13 2d 8c } //00 00 
	condition:
		any of ($a_*)
 
}