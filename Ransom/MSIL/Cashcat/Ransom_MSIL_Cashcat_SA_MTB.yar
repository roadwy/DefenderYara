
rule Ransom_MSIL_Cashcat_SA_MTB{
	meta:
		description = "Ransom:MSIL/Cashcat.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {45 4e 41 42 4c 49 4e 47 20 43 41 54 20 4d 4f 44 45 21 } //ENABLING CAT MODE!  1
		$a_80_1 = {43 61 73 68 43 61 74 20 68 61 73 20 65 6e 63 72 79 70 74 65 64 20 79 6f 75 72 20 66 69 6c 65 73 21 } //CashCat has encrypted your files!  1
		$a_80_2 = {43 61 73 68 43 61 74 52 61 6e 73 6f 6d 77 61 72 65 53 69 6d 75 6c 61 74 6f 72 } //CashCatRansomwareSimulator  1
		$a_80_3 = {70 61 79 20 74 68 65 20 52 61 6e 73 6f 6d 21 } //pay the Ransom!  1
		$a_80_4 = {43 61 73 68 43 61 74 20 53 74 61 72 74 65 64 21 } //CashCat Started!  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}