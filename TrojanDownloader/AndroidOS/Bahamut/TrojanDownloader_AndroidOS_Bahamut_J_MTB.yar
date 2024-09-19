
rule TrojanDownloader_AndroidOS_Bahamut_J_MTB{
	meta:
		description = "TrojanDownloader:AndroidOS/Bahamut.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {6f 72 67 61 2e 75 73 65 72 2e 73 65 63 75 72 65 73 6f 66 74 2e 4d 65 73 73 61 67 65 48 61 6e 64 6c 65 72 } //5 orga.user.securesoft.MessageHandler
		$a_01_1 = {4c 6f 72 67 61 2f 73 65 63 75 72 69 74 79 2f 63 65 72 74 61 72 67 73 2f 53 68 65 6c 6c 53 65 72 76 69 63 65 } //5 Lorga/security/certargs/ShellService
		$a_01_2 = {75 70 64 61 74 65 2e 6a 61 72 } //1 update.jar
		$a_01_3 = {6f 68 61 2e 61 6c 70 69 6e 65 6d 61 70 2e 6e 65 74 } //1 oha.alpinemap.net
		$a_01_4 = {64 6f 53 65 6e 64 4d 65 73 73 61 67 65 54 6f 43 6c 69 65 6e 74 5f 55 49 54 } //1 doSendMessageToClient_UIT
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}