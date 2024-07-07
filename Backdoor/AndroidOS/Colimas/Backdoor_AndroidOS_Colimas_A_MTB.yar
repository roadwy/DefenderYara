
rule Backdoor_AndroidOS_Colimas_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Colimas.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {66 69 6e 64 41 63 63 65 73 73 69 62 69 6c 69 74 79 4e 6f 64 65 49 6e 66 6f 73 42 79 56 69 65 77 49 64 } //1 findAccessibilityNodeInfosByViewId
		$a_01_1 = {42 72 73 6f 77 65 72 5f 52 65 63 6f 72 64 } //1 Brsower_Record
		$a_00_2 = {63 6f 6d 2e 63 73 73 2e 61 64 62 63 6c 69 65 6e 74 } //1 com.css.adbclient
		$a_01_3 = {54 65 6c 65 70 68 6f 6e 65 49 6e 66 6f } //1 TelephoneInfo
		$a_01_4 = {62 61 63 6b 75 70 41 70 70 } //1 backupApp
		$a_01_5 = {63 61 6c 6c 73 6d 73 65 6e 64 } //1 callsmsend
		$a_01_6 = {50 48 4f 4e 45 5f 57 49 46 49 5f 54 52 41 43 4b } //1 PHONE_WIFI_TRACK
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}