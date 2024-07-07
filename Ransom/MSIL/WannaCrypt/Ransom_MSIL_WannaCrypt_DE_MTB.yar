
rule Ransom_MSIL_WannaCrypt_DE_MTB{
	meta:
		description = "Ransom:MSIL/WannaCrypt.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {57 61 6e 6e 61 48 61 70 70 79 } //1 WannaHappy
		$a_81_1 = {41 45 53 5f 45 6e 63 72 79 70 74 } //1 AES_Encrypt
		$a_81_2 = {66 69 6c 65 45 6e 63 72 79 70 74 65 64 } //1 fileEncrypted
		$a_81_3 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}