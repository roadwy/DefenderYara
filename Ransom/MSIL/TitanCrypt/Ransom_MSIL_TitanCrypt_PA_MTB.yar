
rule Ransom_MSIL_TitanCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/TitanCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 00 6c 00 6c 00 20 00 6f 00 66 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 All of your files have been encrypted
		$a_01_1 = {5c 00 5f 00 5f 00 5f 00 52 00 45 00 43 00 4f 00 56 00 45 00 52 00 5f 00 5f 00 46 00 49 00 4c 00 45 00 53 00 5f 00 5f 00 2e 00 74 00 69 00 74 00 61 00 6e 00 63 00 72 00 79 00 70 00 74 00 2e 00 74 00 78 00 74 00 } //1 \___RECOVER__FILES__.titancrypt.txt
		$a_01_2 = {2e 00 74 00 69 00 74 00 61 00 6e 00 63 00 72 00 79 00 70 00 74 00 } //1 .titancrypt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}