
rule Trojan_BAT_RedLineStealer_K_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 0b 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 72 79 70 74 6f 48 65 6c 70 65 72 } //02 00  CryptoHelper
		$a_01_1 = {53 74 72 69 6e 67 44 65 63 72 79 70 74 } //02 00  StringDecrypt
		$a_01_2 = {44 65 76 69 63 65 4d 6f 6e 69 74 6f 72 } //02 00  DeviceMonitor
		$a_01_3 = {49 50 76 34 48 65 6c 70 65 72 } //02 00  IPv4Helper
		$a_01_4 = {53 79 73 74 65 6d 49 6e 66 6f 48 65 6c 70 65 72 } //02 00  SystemInfoHelper
		$a_01_5 = {42 43 52 59 50 54 5f 41 55 54 48 45 4e 54 49 43 41 54 45 44 5f 43 49 50 48 45 52 5f 4d 4f 44 45 5f 49 4e 46 4f } //02 00  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
		$a_01_6 = {42 43 52 59 50 54 5f 4b 45 59 5f 4c 45 4e 47 54 48 53 5f 53 54 52 55 43 54 } //02 00  BCRYPT_KEY_LENGTHS_STRUCT
		$a_01_7 = {42 43 52 59 50 54 5f 4f 41 45 50 5f 50 41 44 44 49 4e 47 5f 49 4e 46 4f } //02 00  BCRYPT_OAEP_PADDING_INFO
		$a_01_8 = {42 43 52 59 50 54 5f 50 53 53 5f 50 41 44 44 49 4e 47 5f 49 4e 46 4f } //02 00  BCRYPT_PSS_PADDING_INFO
		$a_01_9 = {46 69 6c 65 43 6f 70 69 65 72 } //02 00  FileCopier
		$a_01_10 = {46 69 6c 65 53 63 61 6e 6e 65 72 52 75 6c 65 } //00 00  FileScannerRule
	condition:
		any of ($a_*)
 
}