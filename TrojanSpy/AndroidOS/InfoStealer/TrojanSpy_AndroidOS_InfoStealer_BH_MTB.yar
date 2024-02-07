
rule TrojanSpy_AndroidOS_InfoStealer_BH_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.BH!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {44 5a 2e 45 61 67 6c 65 2e 4d 61 73 74 65 72 2e 6d 61 69 6e } //01 00  DZ.Eagle.Master.main
		$a_01_1 = {61 6e 79 77 68 65 72 65 73 6f 66 74 77 61 72 65 2e 62 34 61 2e 72 65 6d 6f 74 65 6c 6f 67 67 65 72 2e 52 65 6d 6f 74 65 4c 6f 67 67 65 72 } //01 00  anywheresoftware.b4a.remotelogger.RemoteLogger
		$a_01_2 = {42 72 69 64 67 65 20 6c 6f 67 67 65 72 20 6e 6f 74 20 65 6e 61 62 6c 65 64 } //00 00  Bridge logger not enabled
	condition:
		any of ($a_*)
 
}