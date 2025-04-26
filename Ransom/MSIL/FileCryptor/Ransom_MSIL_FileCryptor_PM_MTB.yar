
rule Ransom_MSIL_FileCryptor_PM_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 00 52 00 45 00 43 00 55 00 50 00 45 00 52 00 41 00 52 00 5f 00 5f 00 41 00 52 00 51 00 55 00 49 00 56 00 4f 00 53 00 2f 00 2e 00 63 00 6f 00 76 00 63 00 72 00 79 00 70 00 74 00 2e 00 74 00 78 00 74 00 } //1 \RECUPERAR__ARQUIVOS/.covcrypt.txt
		$a_01_1 = {68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 } //1 have been encrypted!
		$a_01_2 = {2e 00 63 00 6f 00 76 00 63 00 72 00 79 00 70 00 74 00 } //1 .covcrypt
		$a_01_3 = {5c 6d 61 74 73 68 75 72 65 2e 70 64 62 } //1 \matshure.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}