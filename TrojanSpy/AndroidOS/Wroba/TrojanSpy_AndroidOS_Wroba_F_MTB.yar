
rule TrojanSpy_AndroidOS_Wroba_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Wroba.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 70 6c 6f 61 64 4c 6f 63 61 74 69 6f 6e 54 6f 53 65 72 76 65 72 } //01 00  uploadLocationToServer
		$a_00_1 = {61 70 69 2f 61 64 64 55 73 65 72 49 6e 66 6f } //01 00  api/addUserInfo
		$a_00_2 = {61 70 69 2f 67 65 74 41 6c 6c 49 6e 63 6f 6d 69 6e 67 } //01 00  api/getAllIncoming
		$a_00_3 = {55 50 6c 6f 61 64 46 69 6c 65 53 65 72 76 69 63 65 } //01 00  UPloadFileService
		$a_00_4 = {73 65 6e 64 4d 73 67 46 6f 72 50 68 6f 6e 65 53 74 61 74 75 73 } //01 00  sendMsgForPhoneStatus
		$a_00_5 = {53 6f 63 6b 65 74 43 6c 69 65 6e 74 } //00 00  SocketClient
	condition:
		any of ($a_*)
 
}