
rule Trojan_AndroidOS_Godfather_D{
	meta:
		description = "Trojan:AndroidOS/Godfather.D,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 5f 41 50 50 4c 4f 47 53 } //1 URL_APPLOGS
		$a_01_1 = {73 65 6e 64 53 6d 73 74 6f 65 72 76 65 72 } //1 sendSmstoerver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_AndroidOS_Godfather_D_2{
	meta:
		description = "Trojan:AndroidOS/Godfather.D,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_00_0 = {2f 6d 70 34 5f 72 65 63 6f 72 64 65 72 2e 70 68 70 } //2 /mp4_recorder.php
		$a_00_1 = {67 65 74 74 6f 70 5f 61 70 70 5f 64 62 } //2 gettop_app_db
		$a_00_2 = {67 6f 64 66 61 74 68 65 72 } //2 godfather
		$a_00_3 = {61 70 70 5f 70 65 72 6d 5f 63 68 65 63 6b } //2 app_perm_check
		$a_00_4 = {73 6d 73 5f 64 65 66 61 75 6c 74 5f 63 6c 69 63 6b } //2 sms_default_click
		$a_00_5 = {61 63 63 65 73 73 5f 75 73 65 5f 73 65 72 76 69 63 65 } //2 access_use_service
		$a_00_6 = {73 65 6e 64 5f 61 6c 6c 5f 70 65 72 6d 69 73 73 69 6f 6e } //2 send_all_permission
		$a_00_7 = {73 74 61 72 74 5f 75 73 73 64 } //2 start_ussd
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2) >=10
 
}