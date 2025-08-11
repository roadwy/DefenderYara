
rule Ransom_MSIL_HiddenTear_BA_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {52 61 6e 73 6f 6d 65 77 61 72 65 2e 70 64 62 } //1 Ransomeware.pdb
		$a_81_1 = {44 65 63 72 79 70 74 20 59 6f 75 72 20 53 79 73 74 65 6d } //1 Decrypt Your System
		$a_81_2 = {45 6e 63 72 79 70 74 69 6f 6e 4b 65 79 } //1 EncryptionKey
		$a_81_3 = {70 61 79 20 79 6f 75 72 20 70 61 79 6d 65 6e 74 20 66 61 73 74 65 72 20 62 65 66 6f 72 65 20 79 6f 75 72 20 73 79 73 74 65 6d 20 63 72 61 73 68 65 64 } //1 pay your payment faster before your system crashed
		$a_81_4 = {54 68 65 20 46 69 6c 65 20 48 61 76 65 20 42 65 65 6e 20 44 65 63 72 79 70 74 65 64 } //1 The File Have Been Decrypted
		$a_81_5 = {63 72 79 70 74 6f 20 61 6e 64 20 69 6e 73 74 72 75 63 74 69 6f 6e 73 20 6f 6e 20 68 6f 77 20 74 6f 20 64 65 63 72 79 70 74 20 74 68 65 20 73 79 73 74 65 6d } //1 crypto and instructions on how to decrypt the system
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}