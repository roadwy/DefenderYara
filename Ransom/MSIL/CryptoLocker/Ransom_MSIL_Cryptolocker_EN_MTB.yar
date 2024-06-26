
rule Ransom_MSIL_Cryptolocker_EN_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 08 00 00 32 00 "
		
	strings :
		$a_81_0 = {64 65 63 72 79 70 74 6f 72 2e 65 78 65 } //32 00  decryptor.exe
		$a_81_1 = {41 4c 4c 20 59 4f 55 52 20 44 41 54 41 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //14 00  ALL YOUR DATA HAVE BEEN ENCRYPTED
		$a_81_2 = {41 45 53 44 65 63 72 79 70 74 } //14 00  AESDecrypt
		$a_81_3 = {45 6e 63 72 79 70 74 65 64 46 69 6c 65 73 } //03 00  EncryptedFiles
		$a_81_4 = {70 61 73 73 77 6f 72 64 34 35 36 37 38 39 30 70 61 73 73 77 6f 72 64 34 35 36 } //03 00  password4567890password456
		$a_81_5 = {76 78 4c 6f 63 6b } //01 00  vxLock
		$a_81_6 = {43 69 70 68 65 72 54 65 78 74 } //01 00  CipherText
		$a_81_7 = {52 53 41 5f 4b 65 79 73 2e 70 75 62 } //00 00  RSA_Keys.pub
	condition:
		any of ($a_*)
 
}