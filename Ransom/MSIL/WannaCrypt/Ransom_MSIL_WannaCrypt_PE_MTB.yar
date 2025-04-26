
rule Ransom_MSIL_WannaCrypt_PE_MTB{
	meta:
		description = "Ransom:MSIL/WannaCrypt.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 00 41 00 4e 00 4e 00 41 00 20 00 43 00 52 00 59 00 20 00 50 00 61 00 64 00 6c 00 6f 00 63 00 6b 00 } //1 WANNA CRY Padlock
		$a_01_1 = {57 00 61 00 6e 00 61 00 5f 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 5f 00 4f 00 72 00 5f 00 32 00 2e 00 5f 00 30 00 } //1 Wana_Decrypt_Or_2._0
		$a_01_2 = {79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 } //3 your files have been encrypted!
		$a_01_3 = {5c 57 61 6e 6e 61 43 72 79 2e 70 64 62 } //1 \WannaCry.pdb
		$a_01_4 = {5c 57 61 6e 61 20 44 65 63 72 79 70 74 20 4f 72 20 32 2e 30 2e 70 64 62 } //1 \Wana Decrypt Or 2.0.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}