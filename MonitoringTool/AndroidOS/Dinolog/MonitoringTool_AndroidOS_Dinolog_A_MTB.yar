
rule MonitoringTool_AndroidOS_Dinolog_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Dinolog.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {48 61 63 6b 69 6e 67 4b 65 79 42 6f 61 72 64 } //1 HackingKeyBoard
		$a_00_1 = {72 65 63 6f 72 64 43 68 61 72 61 63 74 65 72 } //1 recordCharacter
		$a_00_2 = {73 61 76 65 43 68 61 72 61 63 74 65 72 54 6f 44 61 74 61 62 61 73 65 } //1 saveCharacterToDatabase
		$a_00_3 = {67 65 74 48 61 63 6b 69 6e 67 53 74 61 74 75 73 } //1 getHackingStatus
		$a_00_4 = {68 61 63 6b 2f 68 61 63 6b 69 74 2f 70 61 6e 6b 61 6a 2f 6b 65 79 62 6f 61 72 64 6c 69 73 74 65 6e } //1 hack/hackit/pankaj/keyboardlisten
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}