
rule TrojanDownloader_BAT_AgentTesla_NPW_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.NPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 75 73 5f 74 69 63 6b 65 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_80_1 = {53 41 53 41 57 44 53 41 46 53 41 46 57 51 46 57 51 } //SASAWDSAFSAFWQFWQ  01 00 
		$a_80_2 = {46 53 41 2e 46 53 41 } //FSA.FSA  01 00 
		$a_01_3 = {57 47 45 57 47 57 45 } //01 00 
		$a_01_4 = {52 65 76 65 72 73 65 } //01 00 
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 } //01 00 
		$a_01_6 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00 
		$a_81_7 = {47 46 46 51 46 57 51 46 57 51 46 57 51 } //00 00 
	condition:
		any of ($a_*)
 
}