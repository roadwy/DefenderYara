
rule Trojan_AndroidOS_SpyAgent_C_MTB{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 73 70 79 2f 75 70 6c 6f 61 64 4d 6f 62 69 6c 65 43 6f 6e 74 61 63 74 73 } //01 00  /spy/uploadMobileContacts
		$a_01_1 = {2f 75 70 6c 6f 61 64 4d 6f 62 69 6c 65 43 61 6c 6c 4c 6f 67 73 } //01 00  /uploadMobileCallLogs
		$a_01_2 = {2f 75 70 6c 6f 61 64 4d 6f 62 69 6c 65 53 6d 73 73 } //01 00  /uploadMobileSmss
		$a_01_3 = {2f 75 70 6c 6f 61 64 4d 6f 62 69 6c 65 47 70 73 } //01 00  /uploadMobileGps
		$a_01_4 = {2f 61 70 69 2f 76 31 2f 67 6f 6f 64 73 2f 64 65 74 61 69 6c 2f } //00 00  /api/v1/goods/detail/
	condition:
		any of ($a_*)
 
}