
rule Trojan_AndroidOS_Mamont_O_MTB{
	meta:
		description = "Trojan:AndroidOS/Mamont.O!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {64 6f 43 68 61 6e 67 65 44 65 66 61 75 6c 74 53 6d 73 4c 65 67 61 63 79 } //1 doChangeDefaultSmsLegacy
		$a_01_1 = {69 6e 69 74 69 61 6c 69 7a 65 54 65 6c 65 67 72 61 6d 43 72 65 64 65 6e 74 69 61 6c 73 } //1 initializeTelegramCredentials
		$a_01_2 = {6f 6e 41 6c 6c 44 6f 63 73 53 65 6e 74 } //1 onAllDocsSent
		$a_01_3 = {66 65 74 63 68 54 65 6c 65 67 72 61 6d 43 6f 6d 6d 61 6e 64 73 } //1 fetchTelegramCommands
		$a_01_4 = {68 61 6e 64 6c 65 47 65 74 41 6c 6c 53 6d 73 } //1 handleGetAllSms
		$a_01_5 = {73 65 6e 64 53 6d 73 50 75 73 68 4d 65 73 73 61 67 65 } //1 sendSmsPushMessage
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}