
rule Ransom_MSIL_Cobra_PC_MTB{
	meta:
		description = "Ransom:MSIL/Cobra.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 21 } //01 00 
		$a_81_1 = {43 6f 62 72 61 5f 4c 6f 63 6b 65 72 } //01 00 
		$a_00_2 = {53 74 61 72 74 5f 45 6e 63 72 79 70 74 } //01 00 
		$a_03_3 = {5c 43 6f 62 72 61 5f 4c 6f 63 6b 65 72 5c 43 6f 62 72 61 5f 4c 6f 63 6b 65 72 5c 90 02 20 5c 43 6f 62 72 61 5f 4c 6f 63 6b 65 72 2e 70 64 62 90 00 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}