
rule Trojan_BAT_AgentTesla_NSZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 f1 00 00 06 13 06 11 06 7e 90 01 03 04 28 90 01 03 0a 2c 02 19 2a 28 90 01 03 0a 03 6f 90 01 03 0a 13 07 11 05 11 06 11 07 03 6f 90 01 03 0a 17 58 16 28 90 01 03 06 13 08 11 08 2c 07 11 08 6a 1c 6a 33 02 1b 2a 11 05 7e 90 01 03 04 7e 90 01 03 04 72 90 01 03 70 28 90 01 03 06 72 90 01 03 70 28 90 01 03 06 11 06 16 7e 90 01 03 04 28 90 01 03 06 90 00 } //01 00 
		$a_01_1 = {46 6c 75 78 75 73 20 49 44 45 } //00 00  Fluxus IDE
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NSZ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NSZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {0c 07 03 17 da 93 0d 08 03 04 6f 90 01 03 0a 5d 93 13 04 09 11 04 da 13 05 11 05 8c 90 01 03 01 0a 2b 00 90 00 } //01 00 
		$a_01_1 = {59 41 53 55 53 55 41 48 42 4e 5f 39 32 35 } //01 00  YASUSUAHBN_925
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_01_3 = {42 00 75 00 6e 00 00 0b 69 00 66 00 75 00 5f 00 54 00 00 07 65 00 78 00 74 00 00 07 42 00 6f 00 78 } //01 00 
		$a_01_4 = {47 00 65 00 74 00 4d 00 00 0d 65 00 74 00 68 00 6f 00 64 } //01 00 
		$a_01_5 = {42 75 73 69 6e 65 73 73 4d 6f 64 65 6c } //00 00  BusinessModel
	condition:
		any of ($a_*)
 
}