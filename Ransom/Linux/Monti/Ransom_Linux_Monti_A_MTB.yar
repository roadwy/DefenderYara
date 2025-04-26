
rule Ransom_Linux_Monti_A_MTB{
	meta:
		description = "Ransom:Linux/Monti.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {4d 4f 4e 54 49 20 73 74 72 61 69 6e } //5 MONTI strain
		$a_01_1 = {2d 2d 76 6d 6b 69 6c 6c } //1 --vmkill
		$a_01_2 = {45 6e 63 72 79 70 74 65 64 43 6f 6e 74 65 6e 74 49 6e 66 6f } //1 EncryptedContentInfo
		$a_01_3 = {65 6e 63 72 79 70 74 65 64 44 61 74 61 } //1 encryptedData
		$a_01_4 = {76 6d 2d 6c 69 73 74 } //1 vm-list
		$a_01_5 = {2e 6d 6f 6e 74 69 } //5 .monti
		$a_01_6 = {2e 70 75 75 75 6b } //5 .puuuk
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5) >=14
 
}