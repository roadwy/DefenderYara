
rule Trojan_AndroidOS_SpyAgent_A_MTB{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 45 59 5f 50 48 4f 4e 45 5f 49 4d 45 49 } //3 KEY_PHONE_IMEI
		$a_01_1 = {63 6f 6d 2f 73 70 79 73 73 2f 57 77 77 77 77 } //2 com/spyss/Wwwww
		$a_01_2 = {41 4c 4c 5f 53 59 4e 43 5f 43 4f 4e 54 41 43 54 53 } //1 ALL_SYNC_CONTACTS
		$a_01_3 = {73 79 6e 63 43 61 6c 6c 4c 6f 67 73 28 29 } //1 syncCallLogs()
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}