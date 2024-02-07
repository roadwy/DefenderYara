
rule Ransom_MSIL_OMFL_DA_MTB{
	meta:
		description = "Ransom:MSIL/OMFL.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {2e 6f 6d 66 6c } //01 00  .omfl
		$a_81_1 = {53 48 41 33 38 34 } //01 00  SHA384
		$a_81_2 = {64 65 73 6b 74 6f 70 2e 69 6e 69 } //01 00  desktop.ini
		$a_81_3 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00  CreateEncryptor
		$a_81_4 = {63 68 6f 6d 75 72 61 6e 73 6f } //00 00  chomuranso
	condition:
		any of ($a_*)
 
}