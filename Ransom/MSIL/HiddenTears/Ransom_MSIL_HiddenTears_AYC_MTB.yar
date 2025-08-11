
rule Ransom_MSIL_HiddenTears_AYC_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTears.AYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 52 00 45 00 41 00 44 00 5f 00 4d 00 45 00 2e 00 54 00 58 00 54 00 } //2 \Desktop\READ_ME.TXT
		$a_00_1 = {53 00 65 00 63 00 75 00 72 00 65 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 } //1 Secure Encryptor
		$a_00_2 = {72 00 61 00 6e 00 73 00 6f 00 6d 00 30 00 31 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 6b 00 65 00 79 00 73 00 2e 00 70 00 68 00 70 00 } //1 ransom01/createkeys.php
		$a_01_3 = {54 68 69 73 20 69 73 20 61 20 42 6c 6f 63 6b 63 68 61 69 6e } //1 This is a Blockchain
		$a_01_4 = {53 65 6e 64 45 6e 63 72 79 70 74 65 64 4b 65 79 } //1 SendEncryptedKey
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}