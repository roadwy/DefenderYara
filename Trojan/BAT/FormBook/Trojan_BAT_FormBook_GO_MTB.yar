
rule Trojan_BAT_FormBook_GO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_81_0 = {47 5a 49 44 45 4b 4b 4b 4b } //1 GZIDEKKKK
		$a_81_1 = {45 6e 63 72 79 70 74 6f 72 } //1 Encryptor
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_3 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_81_6 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_81_7 = {53 74 72 69 6e 67 42 75 69 6c 64 65 72 } //1 StringBuilder
		$a_81_8 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 MD5CryptoServiceProvider
		$a_81_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_10 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=11
 
}