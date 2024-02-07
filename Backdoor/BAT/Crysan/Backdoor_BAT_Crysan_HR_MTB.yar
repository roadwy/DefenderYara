
rule Backdoor_BAT_Crysan_HR_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.HR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {6b 6a 75 66 64 61 73 2e 65 78 65 } //01 00  kjufdas.exe
		$a_01_1 = {43 6c 69 65 6e 74 5f 00 43 6c 69 65 6e 74 5f 2e 65 78 65 } //01 00 
		$a_01_2 = {53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e } //01 00  System.IO.Compression
		$a_01_3 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_01_4 = {53 79 73 74 65 6d 2e 4c 69 6e 71 } //01 00  System.Linq
		$a_01_5 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  MD5CryptoServiceProvider
		$a_01_6 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //01 00  Rfc2898DeriveBytes
		$a_01_7 = {52 53 41 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  RSACryptoServiceProvider
		$a_01_8 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00  CreateEncryptor
		$a_01_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggableAttribute
	condition:
		any of ($a_*)
 
}