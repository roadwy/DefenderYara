
rule TrojanSpy_AndroidOS_Sharkbot_C{
	meta:
		description = "TrojanSpy:AndroidOS/Sharkbot.C,SIGNATURE_TYPE_DEXHSTR_EXT,33 00 33 00 08 00 00 14 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 69 63 65 2f 46 6f 72 63 65 53 74 6f 70 41 63 63 65 73 73 69 62 69 6c 69 74 79 } //14 00  service/ForceStopAccessibility
		$a_01_1 = {61 70 69 2f 4e 6f 74 69 66 69 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 } //02 00  api/NotificationListener
		$a_01_2 = {61 64 61 70 74 65 72 2f 56 69 72 75 73 41 64 61 70 74 65 72 } //02 00  adapter/VirusAdapter
		$a_01_3 = {61 70 69 2f 73 68 53 63 61 6e 56 69 65 77 } //02 00  api/shScanView
		$a_01_4 = {64 69 61 6c 6f 67 2f 44 69 61 6c 6f 67 41 73 6b 50 65 72 6d 69 73 73 69 6f 6e } //02 00  dialog/DialogAskPermission
		$a_01_5 = {6c 6f 63 6b 2f 72 65 63 65 69 76 65 72 2f 4c 6f 63 6b 52 65 73 74 61 72 74 65 72 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //02 00  lock/receiver/LockRestarterBroadcastReceiver
		$a_01_6 = {6c 6f 63 6b 2f 73 65 72 76 69 63 65 73 2f 4c 6f 61 64 41 70 70 4c 69 73 74 53 65 72 76 69 63 65 } //01 00  lock/services/LoadAppListService
		$a_01_7 = {73 74 61 74 73 63 6f 64 69 63 65 66 69 73 63 61 6c 65 2e 78 79 7a } //00 00  statscodicefiscale.xyz
		$a_00_8 = {5d 04 00 00 7d 0c 05 80 5c 27 00 00 7e 0c 05 80 00 00 01 00 22 00 11 00 cc 21 53 79 73 64 75 70 61 74 65 2e 46 21 4d 54 42 00 00 01 40 05 } //82 31 
	condition:
		any of ($a_*)
 
}