
rule Ransom_MSIL_Filecoder_EQ_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.EQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_81_1 = {50 6f 76 6c 73 6f 6d 77 61 72 65 20 32 2e 30 } //01 00 
		$a_81_2 = {57 69 6e 33 32 5f 53 68 61 64 6f 77 43 6f 70 79 } //01 00 
		$a_81_3 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 62 65 6c 6f 6e 67 20 74 6f 20 75 73 21 } //01 00 
		$a_81_4 = {40 66 6f 72 67 65 74 69 74 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}