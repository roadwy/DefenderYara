
rule Trojan_BAT_CryptInject_MG_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0a 02 8e 69 8d 90 01 03 01 0b 16 0c 2b 13 07 08 02 08 91 06 08 06 8e 69 5d 91 61 b4 9c 08 17 d6 0c 08 02 8e 69 32 e7 90 00 } //01 00 
		$a_01_1 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //01 00  ResumeThread
		$a_01_2 = {53 75 73 70 65 6e 64 54 68 72 65 61 64 } //01 00  SuspendThread
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_5 = {47 65 74 54 65 6d 70 50 61 74 68 } //01 00  GetTempPath
		$a_01_6 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //00 00  MemoryStream
	condition:
		any of ($a_*)
 
}