
rule TrojanSpy_AndroidOS_SAgnt_G_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 65 6e 64 46 69 6c 65 44 65 74 61 69 6c 65 64 } //01 00  sendFileDetailed
		$a_00_1 = {73 65 6e 74 54 6f 73 76 65 72 } //01 00  sentTosver
		$a_00_2 = {73 65 6e 64 43 6f 6e 74 61 63 74 73 44 65 74 61 69 6c 73 } //01 00  sendContactsDetails
		$a_00_3 = {2f 2f 63 61 6c 6c 5f 6c 6f 67 2f 63 61 6c 6c 73 } //01 00  //call_log/calls
		$a_00_4 = {73 65 6e 64 47 45 54 } //01 00  sendGET
		$a_00_5 = {73 65 6e 64 4d 79 53 74 75 66 66 44 65 74 61 69 6c 65 64 } //01 00  sendMyStuffDetailed
		$a_00_6 = {73 74 6f 72 65 47 50 53 } //01 00  storeGPS
		$a_00_7 = {73 65 6e 74 4d 69 63 52 65 63 6f 72 64 69 6e 67 } //00 00  sentMicRecording
	condition:
		any of ($a_*)
 
}