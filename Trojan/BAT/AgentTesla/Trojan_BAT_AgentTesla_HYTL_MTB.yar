
rule Trojan_BAT_AgentTesla_HYTL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HYTL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 74 61 72 5f 41 64 6d 69 72 61 6c } //01 00  Star_Admiral
		$a_81_1 = {42 61 72 62 61 72 61 } //01 00  Barbara
		$a_81_2 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_81_3 = {50 72 69 65 6e } //01 00  Prien
		$a_81_4 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_6 = {53 70 72 69 6e 67 66 69 65 6c 64 } //01 00  Springfield
		$a_81_7 = {00 50 6f 73 69 74 69 6f 6e 00 } //01 00  倀獯瑩潩n
		$a_81_8 = {00 4c 65 76 65 6c 00 } //01 00 
		$a_80_9 = {00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 00 } //  00 00 
	condition:
		any of ($a_*)
 
}