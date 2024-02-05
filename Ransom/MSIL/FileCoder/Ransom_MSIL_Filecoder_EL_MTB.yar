
rule Ransom_MSIL_Filecoder_EL_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {64 65 52 65 61 64 4d 65 21 21 21 2e 74 78 74 } //01 00 
		$a_81_1 = {6b 69 6c 6c 2e 62 61 74 } //01 00 
		$a_81_2 = {6b 69 6c 6c 6d 65 2e 62 61 74 } //01 00 
		$a_81_3 = {64 6f 6e 6f 74 20 63 72 79 20 3a 29 } //01 00 
		$a_81_4 = {2e 63 72 69 6e 67 } //01 00 
		$a_81_5 = {43 72 79 70 74 33 72 } //00 00 
	condition:
		any of ($a_*)
 
}