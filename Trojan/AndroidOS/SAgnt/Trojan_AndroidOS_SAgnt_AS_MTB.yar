
rule Trojan_AndroidOS_SAgnt_AS_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 77 73 79 73 2e 73 79 6e 63 } //5 com.wsys.sync
		$a_01_1 = {75 70 6c 6f 61 64 46 72 69 65 6e 64 44 61 74 61 } //1 uploadFriendData
		$a_01_2 = {77 73 79 73 5f 64 73 } //5 wsys_ds
		$a_01_3 = {55 70 6c 6f 61 64 43 68 61 74 4d 61 6e 61 67 65 72 } //1 UploadChatManager
		$a_01_4 = {45 6e 63 72 79 70 74 55 70 64 61 74 65 44 61 74 61 } //1 EncryptUpdateData
		$a_01_5 = {75 70 6c 6f 61 64 54 65 78 74 4d 65 73 73 61 67 65 54 6f 53 65 72 76 69 63 65 } //1 uploadTextMessageToService
		$a_01_6 = {77 73 79 73 5f 64 73 64 6f 53 79 6e 63 50 68 6f 6e 65 42 6f 6f 6b } //1 wsys_dsdoSyncPhoneBook
		$a_01_7 = {77 73 79 73 5f 64 73 20 75 70 64 61 74 65 55 73 65 72 49 6e 66 6f } //1 wsys_ds updateUserInfo
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=12
 
}