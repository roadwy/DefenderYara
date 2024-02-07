
rule Trojan_Win32_Ekstak_MR_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 10 00 00 01 00 "
		
	strings :
		$a_81_0 = {72 65 74 72 79 5f 75 70 6c 6f 61 64 46 69 6c 65 } //01 00  retry_uploadFile
		$a_81_1 = {50 75 74 50 6c 61 6e } //01 00  PutPlan
		$a_81_2 = {6c 6f 63 61 6c 52 6f 6f 74 } //01 00  localRoot
		$a_81_3 = {44 65 74 65 63 74 65 64 20 57 53 5f 46 54 50 20 73 65 72 76 65 72 2c 20 75 73 69 6e 67 20 72 65 6c 61 74 69 76 65 20 70 61 74 68 73 } //01 00  Detected WS_FTP server, using relative paths
		$a_81_4 = {53 79 6e 63 44 65 6c 65 74 65 52 65 6d 6f 74 65 } //01 00  SyncDeleteRemote
		$a_81_5 = {73 65 6e 64 69 6e 67 43 6f 6d 6d 61 6e 64 } //01 00  sendingCommand
		$a_81_6 = {65 70 73 76 5f 72 65 70 6c 79 } //01 00  epsv_reply
		$a_81_7 = {4d 61 6c 66 6f 72 6d 65 64 20 50 41 53 56 20 72 65 70 6c 79 } //01 00  Malformed PASV reply
		$a_81_8 = {46 74 70 43 6d 64 52 65 73 70 } //01 00  FtpCmdResp
		$a_81_9 = {54 72 75 73 74 65 64 50 65 6f 70 6c 65 } //01 00  TrustedPeople
		$a_81_10 = {70 75 62 4b 65 79 43 75 72 76 65 } //01 00  pubKeyCurve
		$a_81_11 = {65 63 63 56 65 72 69 66 79 48 61 73 68 4b } //01 00  eccVerifyHashK
		$a_81_12 = {6c 6f 61 64 41 6e 79 45 63 63 41 73 6e } //01 00  loadAnyEccAsn
		$a_81_13 = {6c 6f 61 64 45 63 63 50 6f 69 6e 74 } //01 00  loadEccPoint
		$a_81_14 = {73 68 75 74 64 6f 77 6e 43 68 61 6e 6e 65 6c } //01 00  shutdownChannel
		$a_81_15 = {44 62 67 50 72 6f 6d 70 74 } //00 00  DbgPrompt
	condition:
		any of ($a_*)
 
}