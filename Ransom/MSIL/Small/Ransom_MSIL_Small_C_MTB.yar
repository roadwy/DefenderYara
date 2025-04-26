
rule Ransom_MSIL_Small_C_MTB{
	meta:
		description = "Ransom:MSIL/Small.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin delete shadows /all /quiet
		$a_81_1 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } //1 bcdedit /set {default} recoveryenabled no
		$a_81_2 = {65 6e 63 72 79 70 74 65 64 46 69 6c 65 45 78 74 65 6e 73 69 6f 6e } //1 encryptedFileExtension
		$a_81_3 = {45 6e 63 79 70 74 65 64 4b 65 79 } //1 EncyptedKey
		$a_81_4 = {72 65 61 64 5f 69 74 2e 74 78 74 } //1 read_it.txt
		$a_81_5 = {45 6e 63 72 79 70 74 46 69 6c 65 } //1 EncryptFile
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}