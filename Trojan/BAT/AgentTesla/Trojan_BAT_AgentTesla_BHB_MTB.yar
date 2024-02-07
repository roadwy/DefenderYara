
rule Trojan_BAT_AgentTesla_BHB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,25 00 25 00 0b 00 00 0a 00 "
		
	strings :
		$a_81_0 = {58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 00 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 } //0a 00  塘塘塘塘塘塘塘塘塘塘X䅁䅁䅁䅁䅁䅁䅁䅁䅁䅁
		$a_81_1 = {52 65 76 65 72 73 65 00 74 65 78 74 } //0a 00  敒敶獲e整瑸
		$a_81_2 = {54 65 78 54 00 69 4b 65 79 } //01 00 
		$a_81_3 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_81_5 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_81_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_7 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_8 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  MD5CryptoServiceProvider
		$a_81_9 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_81_10 = {49 6e 76 6f 6b 65 4d 65 74 68 6f 64 } //00 00  InvokeMethod
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_BHB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 0b 00 00 0a 00 "
		
	strings :
		$a_81_0 = {69 6d 69 6d 69 6d 69 6d 69 6d 00 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 } //0a 00 
		$a_02_1 = {44 00 53 00 44 00 53 00 90 02 04 44 00 65 00 5f 00 44 00 65 00 66 00 6c 00 61 00 74 00 65 00 90 00 } //0a 00 
		$a_02_2 = {44 53 44 53 90 02 04 44 65 5f 44 65 66 6c 61 74 65 90 00 } //01 00 
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_81_4 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00  GetTypeFromHandle
		$a_81_5 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_6 = {44 65 66 6c 61 74 65 53 74 72 65 61 6d } //01 00  DeflateStream
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_8 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_81_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_10 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //00 00  CompressionMode
	condition:
		any of ($a_*)
 
}