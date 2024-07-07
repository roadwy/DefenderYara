
rule Ransom_MSIL_LockFolder_DA_MTB{
	meta:
		description = "Ransom:MSIL/LockFolder.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {45 6e 63 72 79 70 74 69 6f 6e 20 64 6f 6e 65 21 } //1 Encryption done!
		$a_81_1 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_81_2 = {46 69 6c 65 45 6e 63 72 79 70 74 } //1 FileEncrypt
		$a_81_3 = {4c 6f 63 6b 46 6f 6c 64 65 72 2e 70 64 62 } //1 LockFolder.pdb
		$a_81_4 = {4c 6f 63 6b 46 6f 6c 64 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 LockFolder.Properties.Resources
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}