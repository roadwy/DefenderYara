
rule Ransom_MSIL_Bytelocker_DA_MTB{
	meta:
		description = "Ransom:MSIL/Bytelocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 79 74 65 6c 6f 63 6b 65 72 } //01 00 
		$a_81_1 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00 
		$a_81_2 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_81_3 = {47 65 74 45 78 74 65 6e 73 69 6f 6e } //01 00 
		$a_81_4 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00 
		$a_81_5 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}