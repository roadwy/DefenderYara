
rule Trojan_BAT_AgentTesla_HI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 50 54 49 20 54 68 65 20 66 69 72 73 74 20 70 72 6f 64 } //01 00  RPTI The first prod
		$a_81_1 = {52 50 47 20 54 68 65 20 49 6e 74 65 6c 6c 65 63 74 } //01 00  RPG The Intellect
		$a_81_2 = {59 6f 75 20 6d 75 73 74 20 73 65 6c 65 63 74 20 61 20 67 65 6e 64 65 72 } //01 00  You must select a gender
		$a_81_3 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_81_4 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_81_5 = {50 61 6c 61 64 69 6e } //01 00  Paladin
		$a_81_6 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //01 00  CompressionMode
		$a_81_7 = {46 65 6d 61 6c 65 } //00 00  Female
	condition:
		any of ($a_*)
 
}