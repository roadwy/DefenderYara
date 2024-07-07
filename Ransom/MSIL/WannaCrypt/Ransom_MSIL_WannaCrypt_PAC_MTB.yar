
rule Ransom_MSIL_WannaCrypt_PAC_MTB{
	meta:
		description = "Ransom:MSIL/WannaCrypt.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {57 61 6e 6e 61 43 72 79 70 74 6f 72 } //1 WannaCryptor
		$a_81_1 = {57 72 6f 6e 67 2e 48 61 68 61 68 61 } //1 Wrong.Hahaha
		$a_01_2 = {46 69 6c 65 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 File have been encrypted
		$a_01_3 = {64 69 73 61 62 6c 65 20 79 6f 75 72 20 61 6e 74 69 76 69 72 75 73 20 66 6f 72 20 61 20 77 68 69 6c 65 } //1 disable your antivirus for a while
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}