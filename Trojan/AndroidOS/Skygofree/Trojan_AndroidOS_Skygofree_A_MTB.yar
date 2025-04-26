
rule Trojan_AndroidOS_Skygofree_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Skygofree.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 65 6e 64 50 68 6f 6e 65 43 6f 6e 74 61 63 74 73 } //1 sendPhoneContacts
		$a_00_1 = {75 70 6c 6f 61 64 5f 73 6d 73 2e 70 68 70 } //1 upload_sms.php
		$a_00_2 = {53 65 6e 64 46 69 6c 65 53 79 73 74 65 6d 4c 69 73 74 } //1 SendFileSystemList
		$a_00_3 = {75 70 6c 6f 61 64 5f 69 6e 66 6f 5f 74 65 6c 2e 70 68 70 } //1 upload_info_tel.php
		$a_00_4 = {67 65 74 49 6e 73 74 61 6c 6c 65 64 41 70 70 73 } //1 getInstalledApps
		$a_00_5 = {45 58 50 4c 4f 49 54 20 53 55 43 43 45 53 53 } //1 EXPLOIT SUCCESS
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}