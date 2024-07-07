
rule Trojan_BAT_Coinminer_UF_MTB{
	meta:
		description = "Trojan:BAT/Coinminer.UF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_2 = {41 45 53 5f 44 65 63 72 79 70 74 6f 72 } //1 AES_Decryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_4 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_6 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_7 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
		$a_81_8 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_9 = {00 62 75 66 66 65 72 00 } //1 戀晵敦r
		$a_81_10 = {00 69 6e 70 75 74 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=11
 
}