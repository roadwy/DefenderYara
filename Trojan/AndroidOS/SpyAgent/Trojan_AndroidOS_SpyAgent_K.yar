
rule Trojan_AndroidOS_SpyAgent_K{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.K,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 76 70 74 2e 63 6f 6d 3a 38 31 } //1 dvpt.com:81
		$a_01_1 = {71 75 65 6e 65 5f 65 78 65 63 74 6f 72 5f 63 6f 76 65 72 } //1 quene_exector_cover
		$a_01_2 = {59 69 44 75 4c 69 73 74 41 63 74 69 76 69 74 79 } //1 YiDuListActivity
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_AndroidOS_SpyAgent_K_2{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.K,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 68 65 63 6b 49 73 53 6d 73 50 65 72 6d 69 73 73 69 6f 6e 47 72 61 6e 74 } //2 checkIsSmsPermissionGrant
		$a_01_1 = {55 6e 69 46 65 53 65 72 76 69 63 65 } //2 UniFeService
		$a_01_2 = {53 4d 53 5f 50 45 52 4d 49 53 53 49 4f 4e 5f 50 55 53 48 } //2 SMS_PERMISSION_PUSH
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule Trojan_AndroidOS_SpyAgent_K_3{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.K,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 6c 65 61 73 65 20 63 6f 6e 66 69 67 20 46 54 50 20 73 65 72 76 65 72 } //1 please config FTP server
		$a_01_1 = {6e 6f 20 62 61 73 65 6c 6f 63 20 64 61 74 61 } //1 no baseloc data
		$a_01_2 = {65 6d 61 69 6c 20 6d 73 67 20 74 79 70 65 20 65 72 72 6f 72 } //1 email msg type error
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}