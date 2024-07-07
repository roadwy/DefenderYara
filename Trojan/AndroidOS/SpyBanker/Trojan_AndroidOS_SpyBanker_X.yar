
rule Trojan_AndroidOS_SpyBanker_X{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.X,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_00_0 = {4b 5f 41 4c 4c 5f 4d 45 53 53 41 47 45 5f 55 50 4c 4f 41 44 45 44 } //2 K_ALL_MESSAGE_UPLOADED
		$a_00_1 = {4b 5f 55 50 5f 43 41 4c 4c 5f 49 4e 46 4f } //2 K_UP_CALL_INFO
		$a_00_2 = {4b 5f 41 50 50 53 5f 4c 49 53 54 } //2 K_APPS_LIST
		$a_00_3 = {4b 5f 53 45 4e 44 5f 57 45 42 5f 55 53 45 52 5f 49 4e 46 4f } //2 K_SEND_WEB_USER_INFO
		$a_00_4 = {4b 5f 52 45 43 4f 52 44 5f 4d 45 53 53 41 47 45 } //2 K_RECORD_MESSAGE
		$a_00_5 = {4b 5f 55 50 5f 4c 4f 43 41 54 49 4f 4e } //2 K_UP_LOCATION
		$a_00_6 = {4b 5f 43 41 4c 4c 5f 43 4f 4e 4e 43 54 45 44 } //2 K_CALL_CONNCTED
		$a_00_7 = {4b 5f 47 49 54 5f 48 4f 53 54 } //2 K_GIT_HOST
		$a_00_8 = {4b 5f 47 49 54 5f 47 45 54 5f 48 4f 53 54 5f 54 49 4d 45 52 5f 49 4e 46 4f } //2 K_GIT_GET_HOST_TIMER_INFO
		$a_00_9 = {4b 5f 55 50 5f 4d 45 53 53 41 47 45 5f 49 4e 46 4f } //2 K_UP_MESSAGE_INFO
		$a_00_10 = {4b 5f 55 50 5f 43 4f 4e 54 41 43 54 5f 49 4e 46 4f } //2 K_UP_CONTACT_INFO
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2+(#a_00_8  & 1)*2+(#a_00_9  & 1)*2+(#a_00_10  & 1)*2) >=10
 
}