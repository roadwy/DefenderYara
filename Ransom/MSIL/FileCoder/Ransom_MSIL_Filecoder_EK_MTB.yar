
rule Ransom_MSIL_Filecoder_EK_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {51 57 78 73 49 48 6c 76 64 58 49 67 5a 6d 6c 73 5a 58 4d 67 64 32 56 79 5a 53 42 6c 62 6d 4e 79 65 58 42 30 5a 57 51 } //01 00  QWxsIHlvdXIgZmlsZXMgd2VyZSBlbmNyeXB0ZWQ
		$a_81_1 = {64 69 72 65 63 74 6f 72 79 57 61 6c 6b 65 72 } //01 00  directoryWalker
		$a_81_2 = {67 65 74 5f 46 69 6c 65 50 61 72 73 65 72 } //01 00  get_FileParser
		$a_81_3 = {67 65 74 5f 45 6e 63 72 79 70 74 69 6f 6e 4b 65 79 } //01 00  get_EncryptionKey
		$a_81_4 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 69 6f 6e 4b 65 79 } //01 00  CreateEncryptionKey
		$a_81_5 = {57 72 69 74 65 4d 65 73 73 61 67 65 54 6f 44 6f 63 75 6d 65 6e 74 73 } //00 00  WriteMessageToDocuments
	condition:
		any of ($a_*)
 
}