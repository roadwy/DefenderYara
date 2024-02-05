
rule Ransom_MSIL_Cobra_PD_MTB{
	meta:
		description = "Ransom:MSIL/Cobra.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {2e 43 6f 62 72 61 } //01 00 
		$a_81_1 = {43 6f 62 72 61 5f 4c 6f 63 6b 65 72 40 } //01 00 
		$a_81_2 = {41 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}