
rule TrojanSpy_AndroidOS_Bahamut_C{
	meta:
		description = "TrojanSpy:AndroidOS/Bahamut.C,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 65 78 61 6d 70 6c 65 2e 6a 61 6d 61 61 74 } //1 com.example.jamaat
		$a_00_1 = {49 6e 74 69 61 6c 69 7a 65 53 6f 63 6b 65 74 } //1 IntializeSocket
		$a_00_2 = {53 61 76 65 43 61 6c 6c 4c 6f 67 73 74 6f 44 61 74 61 62 61 73 65 } //1 SaveCallLogstoDatabase
		$a_00_3 = {69 6e 73 65 72 74 54 61 73 6b 41 73 79 6e 63 6b 43 6f 6e 74 61 63 74 73 } //1 insertTaskAsynckContacts
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}