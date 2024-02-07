
rule Trojan_BAT_AgentTesla_NFZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 28 00 00 04 18 9a 20 14 11 00 00 95 5f 7e 28 00 00 04 18 9a 20 9f 08 00 00 95 61 59 81 06 00 00 01 7e 24 00 00 04 7e 2d 00 00 04 36 07 7e 31 00 00 04 } //01 00 
		$a_01_1 = {20 ef 05 00 00 95 2e 03 17 2b 01 16 58 7e 0d 00 00 04 17 9a 1b 95 7e 0d 00 00 04 16 9a 20 88 0b 00 00 95 61 7e 0d 00 00 04 16 9a 20 03 0c 00 00 95 } //01 00 
		$a_01_2 = {57 94 02 28 09 02 00 00 00 fa 25 33 00 16 00 00 01 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NFZ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 14 0d 00 00 95 6e 31 03 16 2b 01 17 17 59 7e 24 00 00 04 20 e4 02 00 00 95 5f 7e 24 00 00 04 20 5b 0d 00 00 95 61 59 81 05 00 00 01 2b 5c 7e 02 00 00 04 1f 47 95 7e 24 00 00 04 20 a6 0f 00 00 } //01 00 
		$a_01_1 = {01 57 94 02 28 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 1b 00 00 00 04 } //01 00 
		$a_01_2 = {41 70 70 44 6f 6d 61 69 6e } //01 00  AppDomain
		$a_01_3 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //01 00  GetFolderPath
		$a_01_4 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_01_5 = {67 65 74 5f 42 61 73 65 44 69 72 65 63 74 6f 72 79 } //00 00  get_BaseDirectory
	condition:
		any of ($a_*)
 
}