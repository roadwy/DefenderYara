
rule MonitoringTool_AndroidOS_PhoneSpy_A_xp{
	meta:
		description = "MonitoringTool:AndroidOS/PhoneSpy.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 73 70 79 3c 2e 3e 36 70 70 2e 77 3c 2e 3e 37 62 62 72 6f 77 73 3c 2e 3e 37 72 } //01 00  com.spy<.>6pp.w<.>7bbrows<.>7r
		$a_01_1 = {63 68 3c 2e 3e 37 63 6b 5f 3c 2e 3e 39 6e 62 6c 6f 63 6b 5f 70 3c 2e 3e 36 73 73 77 6f 72 64 2e 70 68 70 } //01 00  ch<.>7ck_<.>9nblock_p<.>6ssword.php
		$a_01_2 = {63 6f 6d 2e 62 62 6d 2e 3c 2e 3e 39 3c 2e 3e 38 2e 3c 2e 3e 36 63 74 3c 2e 3e 38 76 3c 2e 3e 38 74 3c 2e 3e 38 3c 2e 3e 37 73 2e 43 6f 6e 76 3c 2e 3e 37 72 73 3c 2e 3e 36 74 3c 2e 3e 38 6f 6e 41 63 74 3c 2e 3e 38 76 3c 2e 3e 38 74 79 } //01 00  com.bbm.<.>9<.>8.<.>6ct<.>8v<.>8t<.>8<.>7s.Conv<.>7rs<.>6t<.>8onAct<.>8v<.>8ty
		$a_01_3 = {6f 72 67 2e 3c 2e 3e 36 70 70 73 70 6f 74 2e 3c 2e 3e 36 70 70 72 74 63 2e 53 43 52 45 45 4e 43 41 50 54 55 52 45 } //01 00  org.<.>6ppspot.<.>6pprtc.SCREENCAPTURE
		$a_01_4 = {4c 6f 72 67 2f 77 65 62 72 74 63 2f 76 6f 69 63 65 65 6e 67 69 6e 65 2f 57 65 62 52 74 63 41 75 64 69 6f 52 65 63 6f 72 64 24 41 75 64 69 6f 52 65 63 6f 72 64 54 68 72 65 61 64 } //01 00  Lorg/webrtc/voiceengine/WebRtcAudioRecord$AudioRecordThread
		$a_01_5 = {72 3c 2e 3e 37 63 6f 72 64 3c 2e 3e 38 6e 67 20 56 4f 49 43 45 5f 52 45 43 4f 47 4e 49 54 49 4f 4e } //00 00  r<.>7cord<.>8ng VOICE_RECOGNITION
	condition:
		any of ($a_*)
 
}