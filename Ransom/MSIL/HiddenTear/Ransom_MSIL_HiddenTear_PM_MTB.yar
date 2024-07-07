
rule Ransom_MSIL_HiddenTear_PM_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 6f 6f 64 77 69 6c 6c 20 45 6e 63 72 79 70 74 6f 72 } //1 Goodwill Encryptor
		$a_01_1 = {2e 00 67 00 64 00 77 00 69 00 6c 00 6c 00 } //1 .gdwill
		$a_01_2 = {5c 00 75 00 6e 00 6c 00 6f 00 63 00 6b 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 2e 00 6c 00 6e 00 6b 00 } //1 \unlock your files.lnk
		$a_01_3 = {5c 47 6f 6f 64 77 69 6c 6c 20 45 6e 63 72 79 70 74 6f 72 2e 70 64 62 } //1 \Goodwill Encryptor.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}