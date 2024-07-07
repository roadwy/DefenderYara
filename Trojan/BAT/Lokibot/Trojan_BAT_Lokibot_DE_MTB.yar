
rule Trojan_BAT_Lokibot_DE_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_81_0 = {5f 58 5f 58 30 46 54 5f 46 54 31 } //1 _X_X0FT_FT1
		$a_81_1 = {5f 58 5f 58 30 46 54 5f 46 54 32 } //1 _X_X0FT_FT2
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_6 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_7 = {67 65 74 4d 79 49 50 } //1 getMyIP
		$a_81_8 = {5f 58 5f 54 53 53 33 } //1 _X_TSS3
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=8
 
}