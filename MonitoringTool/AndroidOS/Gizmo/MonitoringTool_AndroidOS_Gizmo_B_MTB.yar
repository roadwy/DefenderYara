
rule MonitoringTool_AndroidOS_Gizmo_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Gizmo.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 0a 00 00 "
		
	strings :
		$a_00_0 = {67 65 74 5f 70 68 6f 6e 65 5f 63 6f 6e 66 69 67 2e 70 68 70 } //1 get_phone_config.php
		$a_00_1 = {53 4d 53 52 65 63 6f 72 64 } //1 SMSRecord
		$a_00_2 = {6c 61 73 74 50 68 6f 6e 65 4c 6f 67 44 61 74 65 } //1 lastPhoneLogDate
		$a_00_3 = {6d 6d 73 5f 69 6e 73 65 72 74 2e 70 68 70 } //1 mms_insert.php
		$a_00_4 = {6c 61 73 74 42 72 6f 77 73 65 72 44 61 74 65 } //1 lastBrowserDate
		$a_00_5 = {74 72 61 63 6b 65 6d 61 69 6c } //1 trackemail
		$a_00_6 = {72 65 63 6f 72 64 63 61 6c 6c 73 } //1 recordcalls
		$a_00_7 = {62 61 63 6b 75 70 44 61 74 61 42 61 73 65 4c 69 76 65 54 6f 53 44 43 61 72 64 } //1 backupDataBaseLiveToSDCard
		$a_00_8 = {66 69 6c 65 73 2f 70 68 6f 6e 65 48 69 73 74 6f 72 79 2e 74 78 74 } //1 files/phoneHistory.txt
		$a_00_9 = {66 69 6c 65 73 2f 64 65 76 69 63 65 69 6e 66 6f 2e 74 78 74 } //1 files/deviceinfo.txt
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=8
 
}