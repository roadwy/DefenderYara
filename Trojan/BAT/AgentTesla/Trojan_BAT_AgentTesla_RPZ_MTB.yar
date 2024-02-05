
rule Trojan_BAT_AgentTesla_RPZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 1f 19 fe 04 16 fe 01 0b 07 2c 17 02 7b 09 00 00 04 7b 1e 00 00 04 06 8f 04 00 00 02 17 7d 12 00 00 04 06 17 58 0a 06 1f 1e fe 04 0c 08 3a 26 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPZ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {13 0d 07 11 09 17 58 09 5d 91 13 0e 11 0c 11 0d 61 11 0e 59 20 00 01 00 00 58 13 0f 07 11 0a 11 0f 20 00 01 00 00 5d d2 9c 00 11 09 17 59 13 09 11 09 16 fe 04 16 fe 01 13 10 11 10 2d a6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPZ_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {7e 1e 00 00 04 0a 06 28 31 00 00 0a 7e 1e 00 00 04 02 12 02 6f 32 00 00 0a 2c 04 08 0b de 11 02 17 28 21 00 00 06 0b de 07 06 28 33 00 00 0a dc 07 2a } //01 00 
		$a_01_1 = {44 69 63 74 69 6f 6e 61 72 79 } //01 00 
		$a_01_2 = {43 6f 6e 63 61 74 } //01 00 
		$a_01_3 = {54 72 79 47 65 74 56 61 6c 75 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPZ_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 16 13 04 2b 21 00 07 09 11 04 6f 96 00 00 0a 13 06 08 12 06 28 97 00 00 0a 6f 98 00 00 0a 00 11 04 17 58 13 04 00 11 04 07 6f 99 00 00 0a 13 08 12 08 28 9a 00 00 0a fe 04 13 07 11 07 2d c6 09 17 58 0d 00 09 07 6f 99 00 00 0a 13 08 12 08 28 9b 00 00 0a fe 04 13 09 11 09 2d a3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPZ_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 33 00 37 00 } //01 00 
		$a_01_1 = {61 00 2d 00 42 00 64 00 6d 00 6b 00 77 00 7a 00 71 00 65 00 63 00 2e 00 62 00 6d 00 70 00 } //01 00 
		$a_01_2 = {52 00 65 00 70 00 6c 00 61 00 63 00 65 00 } //01 00 
		$a_01_3 = {54 00 6f 00 41 00 72 00 72 00 61 00 79 00 } //01 00 
		$a_01_4 = {52 00 65 00 61 00 64 00 43 00 68 00 61 00 72 00 } //01 00 
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_01_6 = {47 65 74 54 79 70 65 } //01 00 
		$a_01_7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_8 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}