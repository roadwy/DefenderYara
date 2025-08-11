
rule Trojan_AndroidOS_SmForw_AV{
	meta:
		description = "Trojan:AndroidOS/SmForw.AV,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 61 6e 63 65 6c 4e 6f 74 4a 6f 69 6e 54 69 6d 65 72 54 61 73 6b } //2 cancelNotJoinTimerTask
		$a_01_1 = {41 50 49 43 41 4c 5f 4e 4f 54 49 46 49 43 41 54 49 4f 4e 5f 41 43 54 49 4f 4e } //2 APICAL_NOTIFICATION_ACTION
		$a_01_2 = {73 74 61 72 74 56 69 64 65 6f 43 61 6c 6c 52 65 73 74 54 69 6d 65 43 6f 75 6e 74 44 6f 77 6e 54 69 6d 65 72 } //2 startVideoCallRestTimeCountDownTimer
		$a_01_3 = {41 43 54 49 4f 4e 5f 56 4f 49 43 45 5f 53 59 53 54 45 4d 5f 43 54 52 4c 5f 53 43 52 45 45 4e } //2 ACTION_VOICE_SYSTEM_CTRL_SCREEN
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=4
 
}