
rule Trojan_BAT_AgentTesla_JAN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {70 0b 06 8e 69 17 59 0c 2b 19 00 07 06 08 8f 90 01 03 01 28 90 01 03 0a 28 90 01 03 0a 0b 00 08 17 59 0c 08 15 fe 02 0d 09 2d df 90 00 } //0a 00 
		$a_02_1 = {01 25 16 1f 2d 9d 6f 90 01 03 0a 0b 00 07 0c 16 0d 2b 1c 08 09 9a 13 04 00 06 11 04 1f 10 28 90 01 03 0a d1 6f 90 01 03 0a 26 00 09 17 58 0d 09 08 8e 69 32 de 90 00 } //01 00 
		$a_81_2 = {46 75 6e 63 74 69 6f 6e 49 6e 69 74 } //01 00  FunctionInit
		$a_81_3 = {4e 61 76 69 67 61 74 69 6f 6e 4c 69 62 } //01 00  NavigationLib
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 } //00 00  FromBase64
	condition:
		any of ($a_*)
 
}