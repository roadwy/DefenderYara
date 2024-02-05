
rule Trojan_BAT_AgentTesla_EZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {03 50 09 03 50 8e 69 6a 5d b7 03 50 09 03 50 8e 69 6a 5d b7 91 07 09 07 8e 69 6a 5d b7 91 61 03 50 09 17 6a d6 03 50 8e 69 6a 5d b7 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 09 17 6a d6 0d 09 08 } //01 00 
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_81_2 = {41 63 74 69 76 61 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_EZ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {23 54 68 69 73 2d 77 6f 72 6c 64 2d 68 61 76 65 2d 6d 61 6e 79 2d 74 68 69 6e 67 73 } //01 00 
		$a_81_1 = {23 4c 65 61 72 6e 2d 65 76 65 72 79 74 68 69 6e 67 2d 62 79 2d 68 65 61 72 74 } //01 00 
		$a_81_2 = {23 46 75 63 6b 2d 74 68 69 73 2d 73 6f 63 69 65 74 79 } //01 00 
		$a_81_3 = {23 59 69 6b 65 73 2d 73 6b 69 64 73 } //01 00 
		$a_81_4 = {23 4d 65 6f 77 74 72 69 78 48 61 78 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_EZ_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {06 20 00 01 00 00 6f 90 01 03 0a 00 06 20 90 01 03 00 6f 90 01 03 0a 00 28 90 01 03 06 28 90 01 03 06 20 90 01 04 73 90 01 03 0a 0b 06 07 06 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 00 06 07 06 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 00 06 17 6f 90 00 } //01 00 
		$a_81_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00 
		$a_81_2 = {4c 6f 40 64 } //01 00 
		$a_81_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}