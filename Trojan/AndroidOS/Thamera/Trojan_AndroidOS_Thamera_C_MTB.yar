
rule Trojan_AndroidOS_Thamera_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Thamera.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 61 6e 6b 6c 32 6b 2e 70 68 70 3f 6b 65 79 3d 31 69 63 79 68 64 38 62 63 37 62 66 71 70 68 6a 65 6d 61 61 26 75 73 65 72 5f 69 64 3d } //01 00  cankl2k.php?key=1icyhd8bc7bfqphjemaa&user_id=
		$a_00_1 = {69 73 53 6d 73 43 61 70 61 62 6c 65 } //01 00  isSmsCapable
		$a_00_2 = {66 69 6e 69 73 68 41 6e 64 52 65 6d 6f 76 65 54 61 73 6b } //01 00  finishAndRemoveTask
		$a_00_3 = {4c 63 6f 6d 2f 73 69 6d 70 6c 65 6d 6f 62 69 6c 65 74 6f 6f 6c 73 2f 6c 61 75 6e 63 68 65 72 2f 61 63 74 69 76 69 74 69 65 73 2f 48 69 64 64 65 6e 49 63 6f 6e 73 41 63 74 69 76 69 74 79 } //00 00  Lcom/simplemobiletools/launcher/activities/HiddenIconsActivity
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_Thamera_C_MTB_2{
	meta:
		description = "Trojan:AndroidOS/Thamera.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 72 67 2f 6a 61 63 6b 61 6a 6b 73 2f 74 68 65 72 2f 53 6d 73 52 65 63 65 69 76 65 72 } //01 00  org/jackajks/ther/SmsReceiver
		$a_01_1 = {53 4d 53 5f 41 50 50 5f 4e 45 57 5f 43 41 4c 4c } //01 00  SMS_APP_NEW_CALL
		$a_01_2 = {53 63 68 65 64 75 6c 65 64 4d 65 73 73 61 67 65 52 65 63 65 69 76 65 72 } //01 00  ScheduledMessageReceiver
		$a_01_3 = {69 73 53 6d 73 43 61 70 61 62 6c 65 } //01 00  isSmsCapable
		$a_01_4 = {63 6f 6d 2e 61 6e 64 72 6f 69 64 2e 63 6f 6e 74 61 63 74 73 2f 63 6f 6e 74 61 63 74 73 } //01 00  com.android.contacts/contacts
		$a_01_5 = {48 65 61 64 6c 65 73 73 53 6d 73 53 65 6e 64 53 65 72 76 69 63 65 } //00 00  HeadlessSmsSendService
	condition:
		any of ($a_*)
 
}