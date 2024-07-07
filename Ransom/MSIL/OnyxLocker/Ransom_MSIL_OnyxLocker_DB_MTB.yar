
rule Ransom_MSIL_OnyxLocker_DB_MTB{
	meta:
		description = "Ransom:MSIL/OnyxLocker.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {4f 6e 79 78 4c 6f 63 6b 65 72 } //1 OnyxLocker
		$a_81_1 = {44 69 72 57 61 6c 6b 65 72 } //1 DirWalker
		$a_81_2 = {57 72 69 74 65 4d 65 73 73 61 67 65 54 6f 44 65 73 6b 74 6f 70 } //1 WriteMessageToDesktop
		$a_81_3 = {67 65 74 5f 45 6e 63 72 79 70 74 69 6f 6e 4b 65 79 } //1 get_EncryptionKey
		$a_81_4 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_5 = {58 78 74 65 61 45 6e 63 72 79 70 74 69 6f 6e 50 72 6f 76 69 64 65 72 } //1 XxteaEncryptionProvider
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}