
rule Trojan_AndroidOS_SpyAgent_HF{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.HF,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 75 63 69 6f 52 65 63 6f 72 64 65 72 41 63 74 69 76 69 74 79 } //02 00  AucioRecorderActivity
		$a_01_1 = {53 65 72 76 65 72 5f 49 73 52 75 6e 43 6c 69 70 62 6f 61 72 64 } //02 00  Server_IsRunClipboard
		$a_01_2 = {63 72 65 61 74 65 46 75 6c 6c 53 63 72 65 65 6e 4e 6f 74 69 66 69 63 61 74 69 6f 6e 57 69 74 68 4d 65 73 73 61 67 65 } //00 00  createFullScreenNotificationWithMessage
	condition:
		any of ($a_*)
 
}