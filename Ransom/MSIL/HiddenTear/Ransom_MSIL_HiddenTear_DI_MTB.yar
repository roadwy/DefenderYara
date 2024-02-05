
rule Ransom_MSIL_HiddenTear_DI_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } //01 00 
		$a_81_1 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //01 00 
		$a_81_2 = {44 45 43 52 59 50 54 5f 4d 45 5f 2e 54 58 54 2e 6c 6f 63 6b 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}