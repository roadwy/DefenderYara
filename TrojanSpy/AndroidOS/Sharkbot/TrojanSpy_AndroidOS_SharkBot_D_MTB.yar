
rule TrojanSpy_AndroidOS_SharkBot_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SharkBot.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {73 65 72 76 69 63 65 2f 46 6f 72 63 65 53 74 6f 70 41 63 63 65 73 73 69 62 69 6c 69 74 79 } //02 00  service/ForceStopAccessibility
		$a_00_1 = {61 64 61 70 74 65 72 2f 56 69 72 75 73 41 64 61 70 74 65 72 } //02 00  adapter/VirusAdapter
		$a_00_2 = {6c 6f 63 6b 2f 72 65 63 65 69 76 65 72 2f 4c 6f 63 6b 52 65 73 74 61 72 74 65 72 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //01 00  lock/receiver/LockRestarterBroadcastReceiver
		$a_00_3 = {6c 6f 63 6b 2f 73 65 72 76 69 63 65 73 2f 4c 6f 61 64 41 70 70 4c 69 73 74 53 65 72 76 69 63 65 } //01 00  lock/services/LoadAppListService
		$a_00_4 = {73 69 67 6d 61 73 74 61 74 73 2e 78 79 7a } //00 00  sigmastats.xyz
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_AndroidOS_SharkBot_D_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/SharkBot.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {35 21 31 00 52 62 90 01 02 d8 02 02 01 d4 22 00 01 59 62 90 01 02 52 63 90 01 02 54 64 90 01 02 44 05 04 02 b0 53 d4 33 00 01 59 63 90 01 02 70 40 90 01 02 26 43 54 62 90 01 02 52 63 90 01 02 44 03 02 03 52 64 90 01 02 44 04 02 04 b0 43 d4 33 00 01 44 02 02 03 48 03 07 01 b7 32 8d 22 d8 03 01 01 4f 02 00 01 01 31 90 00 } //01 00 
		$a_01_1 = {6c 6f 67 73 53 6e 69 66 66 65 72 } //01 00  logsSniffer
		$a_01_2 = {65 6e 61 62 6c 65 4b 65 79 4c 6f 67 67 65 72 } //01 00  enableKeyLogger
		$a_01_3 = {63 6f 6e 66 69 67 53 61 76 65 53 4d 53 } //00 00  configSaveSMS
	condition:
		any of ($a_*)
 
}