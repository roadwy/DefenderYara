
rule Trojan_AndroidOS_FlexiSpy_AS_MTB{
	meta:
		description = "Trojan:AndroidOS/FlexiSpy.AS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 65 6c 65 74 65 53 4d 53 43 6f 6e 74 61 69 6e 69 6e 67 43 6f 6d 6d 61 6e 64 } //01 00  deleteSMSContainingCommand
		$a_00_1 = {64 65 6c 65 74 65 43 61 6c 6c 73 43 6f 6e 74 61 69 6e 69 6e 67 43 6f 64 65 54 6f 52 65 76 65 61 6c 55 49 } //01 00  deleteCallsContainingCodeToRevealUI
		$a_00_2 = {53 65 6e 64 69 6e 67 20 73 69 6e 67 6c 65 2d 70 61 72 74 20 6d 65 73 73 61 67 65 } //01 00  Sending single-part message
		$a_00_3 = {4d 6f 63 6b 50 68 6f 6e 65 49 6e 66 6f 72 6d 61 74 69 6f 6e } //01 00  MockPhoneInformation
		$a_00_4 = {65 76 65 6e 74 49 6e 63 6f 6d 69 6e 67 43 61 6c 6c } //01 00  eventIncomingCall
		$a_00_5 = {63 6f 6d 2e 6d 6f 62 69 6c 65 66 6f 6e 65 78 2e 6d 6f 62 69 6c 65 62 61 63 6b 75 70 2e 72 65 63 65 69 76 65 72 73 2e 43 61 6c 6c 4d 6f 6e 69 74 6f 72 } //00 00  com.mobilefonex.mobilebackup.receivers.CallMonitor
		$a_00_6 = {5d 04 00 00 } //5b 8b 
	condition:
		any of ($a_*)
 
}