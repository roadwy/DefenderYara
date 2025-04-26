
rule Ransom_MSIL_HiddenTear_DQ_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.DQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {4d 6f 6f 6e 57 61 72 65 } //1 MoonWare
		$a_81_1 = {30 2e 35 20 62 69 74 63 6f 6e 73 20 7c 20 41 64 64 72 65 73 73 3a } //1 0.5 bitcons | Address:
		$a_81_2 = {66 69 6c 65 73 54 6f 45 6e 63 72 70 79 74 } //1 filesToEncrpyt
		$a_81_3 = {70 61 72 73 65 41 6e 64 45 6e 63 72 79 70 74 } //1 parseAndEncrypt
		$a_81_4 = {70 61 79 6d 65 6e 74 54 4d 52 5f 54 69 63 6b } //1 paymentTMR_Tick
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}