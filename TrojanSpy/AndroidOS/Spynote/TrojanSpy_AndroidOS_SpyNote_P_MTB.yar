
rule TrojanSpy_AndroidOS_SpyNote_P_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyNote.P!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 70 6c 61 73 68 2e 61 70 70 2e 6d 61 69 6e 2e 52 45 43 4f 52 44 } //1 splash.app.main.RECORD
		$a_01_1 = {65 6e 61 62 6c 65 64 5f 6e 6f 74 69 66 69 63 61 74 69 6f 6e 5f 6c 69 73 74 65 6e 65 72 73 } //1 enabled_notification_listeners
		$a_01_2 = {4c 73 70 6c 61 73 68 2f 61 70 70 2f 53 65 6e 73 6f 72 52 65 73 74 61 72 74 65 72 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //1 Lsplash/app/SensorRestarterBroadcastReceiver
		$a_01_3 = {2f 43 6f 6e 66 69 67 2f 73 79 73 2f 61 70 70 73 2f 6c 6f 67 2f 6c 6f 67 2d } //1 /Config/sys/apps/log/log-
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}