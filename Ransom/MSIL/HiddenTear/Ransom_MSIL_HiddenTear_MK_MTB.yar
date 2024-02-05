
rule Ransom_MSIL_HiddenTear_MK_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 75 73 74 6f 6d 52 43 34 } //01 00 
		$a_81_1 = {66 69 6c 65 45 6e 63 72 79 70 74 69 6f 6e 72 63 34 } //01 00 
		$a_81_2 = {2e 69 6e 66 6f 2e 68 74 61 } //01 00 
		$a_81_3 = {70 61 79 6c 6f 61 64 } //01 00 
		$a_81_4 = {40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d } //01 00 
		$a_81_5 = {5c 52 45 41 44 5f 4d 45 2e 68 74 61 } //01 00 
		$a_81_6 = {64 6f 20 6e 6f 74 20 74 72 79 20 74 6f 20 72 65 6e 61 6d 65 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //00 00 
		$a_00_7 = {5d 04 00 00 4c } //6a 04 
	condition:
		any of ($a_*)
 
}