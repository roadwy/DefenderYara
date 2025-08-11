
rule TrojanSpy_AndroidOS_SpyNote_Q_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyNote.Q!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 6e 76 6f 6b 65 5f 73 70 79 6e 6f 74 65 5f 70 61 79 6c 6f 61 64 } //1 invoke_spynote_payload
		$a_01_1 = {6b 65 79 5f 6c 6f 67 67 65 72 5f 53 74 61 72 74 65 64 } //1 key_logger_Started
		$a_01_2 = {67 65 74 50 61 73 73 4b 65 79 4c 6f 67 67 65 72 54 65 78 74 } //1 getPassKeyLoggerText
		$a_01_3 = {4f 66 66 6c 69 6e 65 4c 6f 67 67 65 72 49 44 } //1 OfflineLoggerID
		$a_01_4 = {67 65 74 4c 6f 63 6b 50 49 4e } //1 getLockPIN
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}