
rule Trojan_BAT_RedLineStealer_MAE_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 8e 69 1f 0f 59 8d 90 01 01 00 00 01 0b 02 1f 0f 07 16 02 8e 69 1f 0f 59 28 90 01 03 0a 1f 10 8d 90 01 01 00 00 01 0c 07 8e 69 08 8e 69 59 8d 90 01 01 00 00 01 0d 07 07 8e 69 1f 10 59 08 16 1f 10 28 90 01 03 0a 07 16 09 16 07 8e 69 08 8e 69 59 28 90 01 03 0a 73 90 01 01 00 00 06 03 06 14 09 08 28 90 01 03 06 13 04 de 90 00 } //01 00 
		$a_81_1 = {67 65 74 5f 49 50 } //01 00  get_IP
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_81_3 = {62 45 6e 63 72 79 70 74 65 64 44 61 74 61 } //01 00  bEncryptedData
		$a_81_4 = {44 65 63 72 79 70 74 42 6c 6f 62 } //01 00  DecryptBlob
		$a_81_5 = {43 68 72 5f 30 5f 4d 5f 65 } //01 00  Chr_0_M_e
		$a_81_6 = {67 65 74 5f 50 6f 73 74 61 6c 43 6f 64 65 } //01 00  get_PostalCode
		$a_81_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_8 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_9 = {53 6c 65 65 70 } //01 00  Sleep
		$a_81_10 = {4f 73 43 72 79 70 74 } //01 00  OsCrypt
		$a_81_11 = {67 65 74 5f 65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //01 00  get_encrypted_key
		$a_81_12 = {44 65 63 72 79 70 74 } //01 00  Decrypt
		$a_81_13 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}