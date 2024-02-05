
rule Ransom_MSIL_Hog_DA_MTB{
	meta:
		description = "Ransom:MSIL/Hog.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {48 6f 67 52 61 6e 73 6f 6d 77 61 72 65 } //01 00 
		$a_81_1 = {45 6e 63 72 79 70 74 46 69 6c 65 } //01 00 
		$a_81_2 = {53 74 72 69 6e 67 45 6e 63 72 79 70 74 69 6f 6e 4b 65 79 } //01 00 
		$a_81_3 = {46 69 6c 65 41 63 63 65 73 73 } //00 00 
	condition:
		any of ($a_*)
 
}