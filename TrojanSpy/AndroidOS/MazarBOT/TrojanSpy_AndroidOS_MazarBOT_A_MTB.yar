
rule TrojanSpy_AndroidOS_MazarBOT_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/MazarBOT.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 0a 00 00 "
		
	strings :
		$a_00_0 = {73 65 74 4f 6e 43 72 65 64 69 74 43 61 72 64 54 79 70 65 43 68 61 6e 67 65 64 4c 69 73 74 65 6e 65 72 } //2 setOnCreditCardTypeChangedListener
		$a_00_1 = {65 78 74 73 2e 77 68 61 74 73 2e 77 61 6b 65 75 70 } //2 exts.whats.wakeup
		$a_00_2 = {68 61 72 64 20 72 65 73 65 74 } //2 hard reset
		$a_00_3 = {2f 63 6f 6d 2f 67 6f 6f 67 6c 65 2f 69 31 38 6e 2f 70 68 6f 6e 65 6e 75 6d 62 65 72 73 2f 64 61 74 61 2f 50 68 6f 6e 65 4e 75 6d 62 65 72 4d 65 74 61 64 61 74 61 50 72 6f 74 6f } //1 /com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto
		$a_01_4 = {52 45 50 4f 52 54 5f 43 41 52 44 5f 44 41 54 41 } //1 REPORT_CARD_DATA
		$a_00_5 = {73 65 6e 64 44 61 74 61 } //1 sendData
		$a_01_6 = {49 4e 54 45 52 43 45 50 54 49 4e 47 5f 45 4e 41 42 4c 45 44 } //1 INTERCEPTING_ENABLED
		$a_00_7 = {67 65 74 52 75 6e 6e 69 6e 67 41 70 70 50 72 6f 63 65 73 73 49 6e 66 6f } //1 getRunningAppProcessInfo
		$a_00_8 = {6b 69 6c 6c 20 63 61 6c 6c } //1 kill call
		$a_00_9 = {67 65 74 41 63 74 69 76 65 4e 65 74 77 6f 72 6b 49 6e 66 6f } //1 getActiveNetworkInfo
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=9
 
}