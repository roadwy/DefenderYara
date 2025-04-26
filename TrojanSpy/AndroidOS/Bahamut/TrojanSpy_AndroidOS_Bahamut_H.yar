
rule TrojanSpy_AndroidOS_Bahamut_H{
	meta:
		description = "TrojanSpy:AndroidOS/Bahamut.H,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 0b 00 00 "
		
	strings :
		$a_00_0 = {67 65 74 42 41 53 45 5f 53 4f 43 4b 45 54 5f 55 52 4c } //1 getBASE_SOCKET_URL
		$a_00_1 = {5f 77 68 61 74 73 61 70 70 44 61 6f } //1 _whatsappDao
		$a_00_2 = {67 65 74 4e 6f 6e 73 65 72 76 65 72 43 6f 6e 74 61 63 74 73 } //1 getNonserverContacts
		$a_00_3 = {24 74 65 6c 65 67 72 61 70 68 44 61 6f } //1 $telegraphDao
		$a_00_4 = {67 65 74 43 61 6c 6c 5f 6c 6f 67 5f 69 64 } //1 getCall_log_id
		$a_00_5 = {67 65 74 46 62 5f 74 69 74 6c 65 5f 61 72 72 61 79 } //1 getFb_title_array
		$a_00_6 = {43 61 6c 6c 4c 6f 67 44 61 6f 5f 49 6d 70 6c } //1 CallLogDao_Impl
		$a_00_7 = {5f 63 6f 6e 69 6f 6e 44 61 6f } //1 _conionDao
		$a_00_8 = {6e 65 77 43 61 6c 6c 4c 6f 67 41 64 64 65 64 } //1 newCallLogAdded
		$a_00_9 = {67 65 74 49 6d 6f 5f 6d 65 73 73 61 67 65 } //1 getImo_message
		$a_00_10 = {67 65 74 53 65 6e 64 5f 74 6f 5f 73 65 72 76 65 72 } //1 getSend_to_server
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=7
 
}