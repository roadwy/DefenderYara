
rule TrojanSpy_AndroidOS_SpyAgent_HJ{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgent.HJ,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 6f 6e 69 74 6f 72 5f 70 68 6f 6e 65 4e 75 6d 62 65 72 2e 74 78 74 } //01 00  monitor_phoneNumber.txt
		$a_00_1 = {41 6e 64 72 6f 69 64 2f 64 61 74 61 2f 63 6f 6d 2e 67 6f 6f 67 6c 65 2e 70 72 6f 67 72 65 73 73 2f 43 61 6c 52 65 63 } //01 00  Android/data/com.google.progress/CalRec
		$a_00_2 = {69 73 65 6e 64 4f 74 68 65 72 43 61 6c 6c } //01 00  isendOtherCall
		$a_00_3 = {4c 63 6f 6d 2f 67 6f 6f 67 6c 65 2f 70 72 6f 67 72 65 73 73 2f 57 69 66 69 43 68 65 63 6b 54 61 73 6b } //01 00  Lcom/google/progress/WifiCheckTask
		$a_00_4 = {63 61 6c 6c 5f 70 64 20 69 6e 20 70 61 75 73 65 52 65 63 6f 72 64 } //01 00  call_pd in pauseRecord
		$a_00_5 = {73 74 61 72 74 43 6f 6e 6e 65 63 74 53 65 72 76 69 63 65 54 61 73 6b 5f 57 69 74 68 55 73 62 43 6f 6e 6e 65 63 74 65 64 } //00 00  startConnectServiceTask_WithUsbConnected
		$a_00_6 = {5d 04 00 } //00 07 
	condition:
		any of ($a_*)
 
}