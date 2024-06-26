
rule Trojan_BAT_FormBook_GO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_81_0 = {47 5a 49 44 45 4b 4b 4b 4b } //01 00  GZIDEKKKK
		$a_81_1 = {45 6e 63 72 79 70 74 6f 72 } //01 00  Encryptor
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_3 = {44 65 63 72 79 70 74 } //01 00  Decrypt
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_5 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_81_6 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_81_7 = {53 74 72 69 6e 67 42 75 69 6c 64 65 72 } //01 00  StringBuilder
		$a_81_8 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  MD5CryptoServiceProvider
		$a_81_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_10 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}