
rule TrojanSpy_AndroidOS_SpyAgent_H{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgent.H,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 0a 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 70 69 2f 6a 75 72 79 50 61 6e 64 65 6d 69 63 } //01 00  api/juryPandemic
		$a_00_1 = {69 73 50 72 6f 74 65 63 74 65 64 54 65 78 74 45 6e 61 62 6c 65 64 } //01 00  isProtectedTextEnabled
		$a_00_2 = {66 65 74 63 68 54 65 6c 65 67 72 61 6d 43 6f 6e 74 61 63 74 4e 61 6d 65 } //01 00  fetchTelegramContactName
		$a_00_3 = {61 70 69 2f 72 6f 61 6d 69 6e 67 53 74 61 6d 6d 65 72 } //01 00  api/roamingStammer
		$a_00_4 = {66 65 74 63 68 57 68 61 74 73 41 70 70 42 75 73 69 6e 65 73 73 43 6f 6e 74 61 63 74 4e 61 6d 65 } //01 00  fetchWhatsAppBusinessContactName
		$a_00_5 = {73 65 61 72 63 68 46 42 4d 65 73 73 61 67 65 73 } //01 00  searchFBMessages
		$a_00_6 = {66 69 6e 64 46 42 54 69 74 6c 65 } //01 00  findFBTitle
		$a_00_7 = {76 69 62 65 72 54 69 74 6c 65 41 72 72 61 79 } //01 00  viberTitleArray
		$a_00_8 = {77 68 61 74 73 41 70 70 42 75 73 69 6e 65 73 73 54 69 74 6c 65 } //01 00  whatsAppBusinessTitle
		$a_00_9 = {66 62 54 69 74 6c 65 41 72 72 61 79 } //00 00  fbTitleArray
	condition:
		any of ($a_*)
 
}