
rule Trojan_BAT_AgentTesla_EV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 91 03 07 03 6f 90 01 03 0a 5d 17 6f 90 01 03 0a 28 90 01 03 0a 61 28 90 01 03 0a 9c 07 17 58 0b 07 02 8e 69 32 d6 90 00 } //1
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_2 = {45 6e 63 72 79 70 74 44 65 63 72 79 70 74 } //1 EncryptDecrypt
		$a_81_3 = {67 70 72 6f 67 65 6a 67 65 72 } //1 gprogejger
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Trojan_BAT_AgentTesla_EV_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_81_0 = {65 62 37 39 66 34 38 38 2d 38 62 31 30 2d 34 31 63 62 2d 62 37 63 38 2d 31 31 38 63 38 39 35 31 30 39 63 65 } //1 eb79f488-8b10-41cb-b7c8-118c895109ce
		$a_81_1 = {44 65 66 6c 61 74 65 53 74 72 65 61 6d } //1 DeflateStream
		$a_81_2 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_81_3 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //1 SymmetricAlgorithm
		$a_81_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_5 = {43 72 79 70 74 6f 67 72 61 70 68 79 } //1 Cryptography
		$a_81_6 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_7 = {47 61 62 43 6f 70 79 50 61 73 74 65 } //1 GabCopyPaste
		$a_81_8 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_9 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_10 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_11 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_81_12 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_13 = {52 53 41 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 RSACryptoServiceProvider
		$a_81_14 = {31 31 31 31 31 2d 32 32 32 32 32 2d 35 30 30 30 31 2d 30 30 30 30 31 } //1 11111-22222-50001-00001
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1) >=15
 
}