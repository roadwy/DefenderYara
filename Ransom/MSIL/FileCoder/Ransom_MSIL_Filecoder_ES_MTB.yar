
rule Ransom_MSIL_Filecoder_ES_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 43 5f 4c 6f 67 6f 5f } //01 00 
		$a_81_1 = {42 69 74 63 6f 69 6e } //01 00 
		$a_81_2 = {45 78 74 65 6e 73 69 6f 6e 73 54 6f 45 6e 63 72 79 70 74 } //01 00 
		$a_81_3 = {61 6c 77 61 79 73 5f 65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_81_4 = {47 65 74 45 6e 63 72 79 70 74 65 64 46 69 6c 65 73 } //01 00 
		$a_81_5 = {41 6c 62 43 72 79 } //01 00 
		$a_81_6 = {41 6c 62 43 72 79 20 32 2e 30 } //00 00 
	condition:
		any of ($a_*)
 
}