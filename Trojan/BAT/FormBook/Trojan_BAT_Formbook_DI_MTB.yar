
rule Trojan_BAT_Formbook_DI_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 68 61 74 4d 65 73 73 61 67 65 51 75 65 75 65 2e 43 68 61 74 2e 72 65 73 6f 75 72 63 65 73 } //01 00  ChatMessageQueue.Chat.resources
		$a_81_1 = {43 6f 72 65 2e 4e 75 6d 65 72 6f } //01 00  Core.Numero
		$a_81_2 = {64 69 72 65 63 74 44 6f 77 6e 6c 6f 61 64 55 72 6c } //01 00  directDownloadUrl
		$a_81_3 = {43 72 65 61 74 65 51 75 65 75 65 } //01 00  CreateQueue
		$a_81_4 = {43 68 61 74 20 51 75 65 75 65 } //01 00  Chat Queue
		$a_81_5 = {52 6f 6d 61 6e 73 } //01 00  Romans
		$a_81_6 = {40 75 77 65 63 2e 65 64 75 } //01 00  @uwec.edu
		$a_81_7 = {62 69 62 6c 69 6a 61 2e 6e 65 74 } //00 00  biblija.net
	condition:
		any of ($a_*)
 
}