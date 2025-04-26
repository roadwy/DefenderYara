
rule Ransom_MSIL_CornCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/CornCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 52 00 45 00 41 00 44 00 5f 00 49 00 54 00 2e 00 74 00 78 00 74 00 2e 00 66 00 75 00 63 00 6b 00 75 00 6e 00 69 00 63 00 6f 00 72 00 6e 00 68 00 74 00 72 00 68 00 72 00 74 00 6a 00 72 00 6a 00 79 00 } //1 \Desktop\READ_IT.txt.fuckunicornhtrhrtjrjy
		$a_01_1 = {2e 00 66 00 75 00 63 00 6b 00 75 00 6e 00 69 00 63 00 6f 00 72 00 6e 00 68 00 74 00 72 00 68 00 72 00 74 00 6a 00 72 00 6a 00 79 00 } //1 .fuckunicornhtrhrtjrjy
		$a_01_2 = {5c 00 72 00 61 00 6e 00 73 00 6f 00 6d 00 2e 00 6a 00 70 00 67 00 } //1 \ransom.jpg
		$a_01_3 = {66 00 75 00 63 00 6b 00 75 00 6e 00 69 00 63 00 6f 00 72 00 6e 00 } //1 fuckunicorn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}