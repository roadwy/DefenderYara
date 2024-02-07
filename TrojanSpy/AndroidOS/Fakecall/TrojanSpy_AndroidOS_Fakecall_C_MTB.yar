
rule TrojanSpy_AndroidOS_Fakecall_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakecall.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 73 65 63 75 72 65 6e 65 74 2f 61 73 73 69 73 74 61 6e 74 2f 50 68 6f 6e 65 43 61 6c 6c 41 63 74 69 76 69 74 79 } //01 00  com/securenet/assistant/PhoneCallActivity
		$a_00_1 = {69 6e 6a 65 63 74 49 66 4e 65 65 64 65 64 49 6e } //01 00  injectIfNeededIn
		$a_01_2 = {54 52 41 4e 53 41 43 54 49 4f 4e 5f 6f 6e 4f 75 74 67 6f 69 6e 67 43 61 6c 6c } //01 00  TRANSACTION_onOutgoingCall
		$a_01_3 = {52 45 51 55 45 53 54 5f 52 45 44 49 52 45 43 54 5f 43 41 4c 4c } //01 00  REQUEST_REDIRECT_CALL
		$a_00_4 = {73 6d 73 49 6e 66 6f 4c 69 73 74 } //01 00  smsInfoList
		$a_00_5 = {67 65 74 4d 6f 62 69 6c 65 4e 4f } //01 00  getMobileNO
		$a_00_6 = {6c 61 73 74 52 65 63 6f 72 64 69 6e 67 44 75 72 61 74 69 6f 6e } //00 00  lastRecordingDuration
	condition:
		any of ($a_*)
 
}