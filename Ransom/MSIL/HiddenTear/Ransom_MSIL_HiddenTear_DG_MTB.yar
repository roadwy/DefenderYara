
rule Ransom_MSIL_HiddenTear_DG_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 74 68 61 74 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_81_1 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //01 00 
		$a_81_2 = {49 6d 70 6f 72 74 61 6e 74 2e 74 78 74 } //01 00 
		$a_81_3 = {44 61 72 6b 57 6f 72 6c 64 } //01 00 
		$a_81_4 = {2e 64 61 72 6b } //00 00 
	condition:
		any of ($a_*)
 
}