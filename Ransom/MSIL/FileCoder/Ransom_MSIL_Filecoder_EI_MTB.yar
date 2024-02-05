
rule Ransom_MSIL_Filecoder_EI_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.EI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {50 6f 76 6c 73 6f 6d 77 61 72 65 } //01 00 
		$a_81_1 = {57 69 6e 33 32 5f 53 68 61 64 6f 77 43 6f 70 79 } //01 00 
		$a_81_2 = {44 65 63 72 79 70 74 65 64 3a } //01 00 
		$a_81_3 = {45 6e 63 72 79 70 74 65 64 3a } //01 00 
		$a_81_4 = {6c 6f 76 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}