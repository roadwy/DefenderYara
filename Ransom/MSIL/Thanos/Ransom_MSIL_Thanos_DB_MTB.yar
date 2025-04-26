
rule Ransom_MSIL_Thanos_DB_MTB{
	meta:
		description = "Ransom:MSIL/Thanos.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {57 6f 72 6b 65 72 43 72 79 70 74 65 72 } //1 WorkerCrypter
		$a_81_1 = {43 68 65 63 6b 44 65 66 65 6e 64 65 72 } //1 CheckDefender
		$a_81_2 = {44 69 73 54 61 73 6b 4d 61 6e 61 67 65 72 } //1 DisTaskManager
		$a_81_3 = {4c 6f 63 6b 65 64 46 69 6c 65 73 } //1 LockedFiles
		$a_81_4 = {45 6e 63 72 79 70 74 65 64 46 69 6c 65 73 } //1 EncryptedFiles
		$a_81_5 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}