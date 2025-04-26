
rule TrojanSpy_AndroidOS_Piom_AT{
	meta:
		description = "TrojanSpy:AndroidOS/Piom.AT,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 43 6f 6e 74 61 63 73 44 61 6f } //1 getContacsDao
		$a_01_1 = {44 65 6c 65 74 65 41 6c 6c 53 6d 73 } //1 DeleteAllSms
		$a_01_2 = {5f 69 6e 66 6f 57 68 61 74 73 61 70 70 4d 65 73 73 61 67 65 } //1 _infoWhatsappMessage
		$a_00_3 = {68 74 74 70 73 3a 2f 2f 72 34 64 63 33 62 74 62 79 7a 69 70 30 65 64 6b 62 79 6b 62 31 71 74 65 75 6c 77 62 2e 64 65 } //1 https://r4dc3btbyzip0edkbykb1qteulwb.de
		$a_01_4 = {4c 63 6f 6d 2f 63 75 73 74 6f 6d 2f 76 63 6f 70 79 } //1 Lcom/custom/vcopy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}