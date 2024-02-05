
rule Ransom_MSIL_Filecoder_FB_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.FB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {2e 6c 6f 63 6b 65 64 } //01 00 
		$a_81_1 = {4d 61 6d 6d 6f 74 69 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00 
		$a_81_2 = {6d 61 6d 6d 6f 74 69 2e 6a 70 67 } //01 00 
		$a_81_3 = {41 4c 4c 20 46 49 4c 45 53 20 4c 4f 41 44 45 44 2e 2e 2e } //01 00 
		$a_81_4 = {42 72 75 74 65 20 46 6f 72 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}