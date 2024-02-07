
rule Trojan_AndroidOS_WolfRAT_A{
	meta:
		description = "Trojan:AndroidOS/WolfRAT.A,SIGNATURE_TYPE_DEXHSTR_EXT,0d 00 0d 00 0e 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 63 72 65 65 6e 52 65 63 6f 72 64 65 72 } //01 00  ScreenRecorder
		$a_00_1 = {54 68 72 65 61 64 20 52 65 63 } //01 00  Thread Rec
		$a_00_2 = {54 68 72 65 61 64 20 73 6c 65 65 70 20 3a 20 } //01 00  Thread sleep : 
		$a_00_3 = {79 79 2f 4d 4d 2f 64 64 20 48 48 3a 6d 6d 3a 73 73 } //01 00  yy/MM/dd HH:mm:ss
		$a_00_4 = {64 75 6d 70 73 79 73 20 61 63 74 69 76 69 74 79 20 7c 20 67 72 65 70 20 22 52 75 6e 20 23 22 20 7c 20 67 72 65 70 20 2d 76 20 53 63 72 65 65 6e 52 65 63 6f 72 64 65 72 41 63 74 69 76 69 74 79 20 7c 20 68 65 61 64 20 2d 6e 20 31 } //01 00  dumpsys activity | grep "Run #" | grep -v ScreenRecorderActivity | head -n 1
		$a_00_5 = {63 6f 6d 2e 63 6f 6e 6e 65 63 74 } //01 00  com.connect
		$a_00_6 = {63 6f 6d 2e 77 68 61 74 73 61 70 70 2f 2e 76 6f 69 70 63 61 6c 6c 69 6e 67 2e 56 6f 69 70 41 63 74 69 76 69 74 79 56 32 } //01 00  com.whatsapp/.voipcalling.VoipActivityV2
		$a_00_7 = {63 6f 6d 2e 66 61 63 65 62 6f 6f 6b 2e 6f 72 63 61 2f 63 6f 6d 2e 66 61 63 65 62 6f 6f 6b 2e 72 74 63 2e 61 63 74 69 76 69 74 69 65 73 2e 57 65 62 72 74 63 49 6e 63 61 6c 6c 46 72 61 67 6d 65 6e 74 48 6f 73 74 41 63 74 69 76 69 74 79 } //01 00  com.facebook.orca/com.facebook.rtc.activities.WebrtcIncallFragmentHostActivity
		$a_00_8 = {6a 70 2e 6e 61 76 65 72 2e 6c 69 6e 65 2e 61 6e 64 72 6f 69 64 2f 63 6f 6d 2e 6c 69 6e 65 63 6f 72 70 2e 76 6f 69 70 2e 75 69 2e 62 61 73 65 2e 56 6f 49 50 53 65 72 76 69 63 65 41 63 74 69 76 69 74 79 } //01 00  jp.naver.line.android/com.linecorp.voip.ui.base.VoIPServiceActivity
		$a_00_9 = {63 68 6b 53 74 61 72 74 52 65 63 20 3a 20 6f 70 65 6e 20 } //01 00  chkStartRec : open 
		$a_00_10 = {63 68 6b 53 74 61 72 74 52 65 63 20 3a 20 63 6c 6f 73 65 20 } //01 00  chkStartRec : close 
		$a_00_11 = {63 6f 6d 2e 73 65 72 65 6e 65 67 69 61 6e 74 2e 73 65 72 76 69 63 65 2e 53 63 72 65 65 6e 52 65 63 6f 72 64 65 72 53 65 72 76 69 63 65 2e 41 43 54 49 4f 4e 5f 53 54 4f 50 } //01 00  com.serenegiant.service.ScreenRecorderService.ACTION_STOP
		$a_00_12 = {6d 65 64 69 61 5f 70 72 6f 6a 65 63 74 69 6f 6e } //01 00  media_projection
		$a_00_13 = {69 73 4e 61 74 69 76 65 52 75 6e 6e 69 6e 67 20 65 72 72 20 3a } //00 00  isNativeRunning err :
	condition:
		any of ($a_*)
 
}