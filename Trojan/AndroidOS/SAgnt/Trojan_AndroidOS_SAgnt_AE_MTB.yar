
rule Trojan_AndroidOS_SAgnt_AE_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AE!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 65 76 41 64 6d 69 6e 44 69 73 61 62 6c 65 72 } //1 DevAdminDisabler
		$a_01_1 = {65 78 74 73 2f 64 65 6e 6d 61 72 6b } //1 exts/denmark
		$a_01_2 = {72 65 61 64 4d 65 73 73 61 67 65 73 46 72 6f 6d 44 65 76 69 63 65 44 42 } //1 readMessagesFromDeviceDB
		$a_01_3 = {67 65 74 41 70 70 4c 69 73 74 } //1 getAppList
		$a_01_4 = {52 45 50 4f 52 54 5f 49 4e 43 4f 4d 49 4e 47 5f 4d 45 53 53 41 47 45 } //1 REPORT_INCOMING_MESSAGE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}