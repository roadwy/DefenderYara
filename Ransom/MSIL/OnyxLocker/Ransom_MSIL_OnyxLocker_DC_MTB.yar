
rule Ransom_MSIL_OnyxLocker_DC_MTB{
	meta:
		description = "Ransom:MSIL/OnyxLocker.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {52 45 43 4f 56 45 52 59 20 49 4e 53 54 52 55 43 54 49 4f 4e 53 } //1 RECOVERY INSTRUCTIONS
		$a_81_1 = {2e 64 65 73 74 72 6f 79 65 64 } //1 .destroyed
		$a_81_2 = {64 69 72 65 63 74 6f 72 79 57 61 6c 6b 65 72 } //1 directoryWalker
		$a_81_3 = {67 65 74 5f 46 69 6c 65 50 61 72 73 65 72 } //1 get_FileParser
		$a_81_4 = {57 72 69 74 65 46 69 6c 65 42 79 74 65 73 } //1 WriteFileBytes
		$a_81_5 = {57 72 69 74 65 4d 65 73 73 61 67 65 54 6f 44 6f 63 75 6d 65 6e 74 73 } //1 WriteMessageToDocuments
		$a_81_6 = {53 68 6f 77 57 69 6e 64 6f 77 } //1 ShowWindow
		$a_81_7 = {67 65 74 5f 45 6e 63 72 79 70 74 69 6f 6e 4b 65 79 } //1 get_EncryptionKey
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}