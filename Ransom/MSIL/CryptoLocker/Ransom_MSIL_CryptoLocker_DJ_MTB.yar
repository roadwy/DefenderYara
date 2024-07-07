
rule Ransom_MSIL_CryptoLocker_DJ_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {68 61 70 70 79 57 61 6c 6c 65 74 } //1 happyWallet
		$a_81_1 = {52 53 41 45 6e 63 72 79 70 74 } //1 RSAEncrypt
		$a_81_2 = {67 65 74 5f 45 78 74 65 6e 73 69 6f 6e } //1 get_Extension
		$a_81_3 = {42 49 54 43 4f 49 4e 5f 41 44 44 52 45 53 53 } //1 BITCOIN_ADDRESS
		$a_81_4 = {66 75 63 6b 33 36 30 } //1 fuck360
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Ransom_MSIL_CryptoLocker_DJ_MTB_2{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 08 00 00 "
		
	strings :
		$a_81_0 = {72 61 69 6e 62 6f 77 63 72 79 70 74 65 72 } //20 rainbowcrypter
		$a_81_1 = {2e 52 45 59 50 54 53 4f 4e } //20 .REYPTSON
		$a_81_2 = {2e 6c 6f 63 6b 65 64 } //10 .locked
		$a_81_3 = {2e 6f 6e 69 6f 6e } //10 .onion
		$a_81_4 = {45 6e 63 72 79 70 74 46 69 6c 65 } //5 EncryptFile
		$a_81_5 = {65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 } //5 encryptedUsername
		$a_81_6 = {61 65 73 65 6e 63 72 79 70 74 65 64 } //1 aesencrypted
		$a_81_7 = {43 6f 6d 6f 5f 52 65 63 75 70 65 72 61 72 5f 54 75 73 5f 46 69 63 68 65 72 6f 73 2e 74 78 74 } //1 Como_Recuperar_Tus_Ficheros.txt
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*5+(#a_81_5  & 1)*5+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=36
 
}