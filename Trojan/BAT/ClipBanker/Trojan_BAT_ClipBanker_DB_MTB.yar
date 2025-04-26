
rule Trojan_BAT_ClipBanker_DB_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {53 79 73 74 65 6d 53 6f 63 6b 65 74 54 61 73 6b 73 } //1 SystemSocketTasks
		$a_81_1 = {61 73 64 61 73 66 73 61 } //1 asdasfsa
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_4 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_81_5 = {44 65 63 6f 6d 70 72 65 73 73 } //1 Decompress
		$a_81_6 = {44 65 63 72 79 70 74 } //1 Decrypt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}