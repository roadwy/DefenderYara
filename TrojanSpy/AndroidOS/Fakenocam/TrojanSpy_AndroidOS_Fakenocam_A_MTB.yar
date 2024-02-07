
rule TrojanSpy_AndroidOS_Fakenocam_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakenocam.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3f 74 79 70 65 3d 63 6f 6d 65 4f 6e 43 61 6c 6c } //01 00  ?type=comeOnCall
		$a_00_1 = {61 32 5f 68 79 75 6e 64 61 65 63 61 72 64 2e 6d 70 33 } //01 00  a2_hyundaecard.mp3
		$a_00_2 = {2f 48 65 61 72 74 42 65 61 74 52 65 63 65 69 76 65 72 } //01 00  /HeartBeatReceiver
		$a_00_3 = {64 65 6c 65 74 65 43 61 6c 6c 4c 6f 67 } //01 00  deleteCallLog
		$a_00_4 = {70 6d 20 69 6e 73 74 61 6c 6c 20 2d 72 } //01 00  pm install -r
		$a_00_5 = {6b 69 6c 6c 42 61 63 6b 67 72 6f 75 6e 64 50 72 6f 63 65 73 73 65 73 } //00 00  killBackgroundProcesses
		$a_00_6 = {5d 04 00 00 } //e7 34 
	condition:
		any of ($a_*)
 
}