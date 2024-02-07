
rule Trojan_BAT_RedLineStealer_MYA_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 67 69 73 74 65 72 46 69 6c 65 } //01 00  RegisterFile
		$a_01_1 = {42 43 52 59 50 54 5f 41 55 54 48 45 4e 54 49 43 41 54 45 44 5f 43 49 50 48 45 52 5f 4d 4f 44 45 } //01 00  BCRYPT_AUTHENTICATED_CIPHER_MODE
		$a_01_2 = {44 65 63 72 79 70 74 42 6c 6f 62 } //01 00  DecryptBlob
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_4 = {43 6c 69 65 6e 74 43 72 65 64 65 6e 74 69 61 6c 73 } //01 00  ClientCredentials
		$a_01_5 = {5f 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 24 00 } //01 00  _Encrypted$
		$a_01_6 = {51 00 57 00 70 00 76 00 64 00 32 00 46 00 75 00 63 00 79 00 } //01 00  QWpvd2Fucy
		$a_01_7 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_01_8 = {6f 73 5f 63 72 79 70 74 } //01 00  os_crypt
		$a_01_9 = {67 65 74 5f 65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //00 00  get_encrypted_key
	condition:
		any of ($a_*)
 
}