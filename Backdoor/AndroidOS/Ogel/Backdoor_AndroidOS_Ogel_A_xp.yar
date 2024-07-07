
rule Backdoor_AndroidOS_Ogel_A_xp{
	meta:
		description = "Backdoor:AndroidOS/Ogel.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 09 00 00 "
		
	strings :
		$a_00_0 = {47 65 74 44 65 66 69 6e 65 42 61 63 6b 75 70 48 6f 73 74 } //1 GetDefineBackupHost
		$a_00_1 = {5f 69 73 4b 69 6c 6c 4d 79 53 65 6c 66 } //1 _isKillMySelf
		$a_00_2 = {5f 61 62 6f 72 74 42 72 6f 61 64 63 61 73 74 } //1 _abortBroadcast
		$a_00_3 = {5f 68 61 6e 6c 64 53 65 6e 64 4d 73 67 50 65 6e 64 69 6e 67 49 6e 74 65 6e 74 } //1 _hanldSendMsgPendingIntent
		$a_00_4 = {72 65 42 6f 6f 74 4d 73 67 53 63 72 65 65 6e 52 65 63 65 69 76 65 72 } //1 reBootMsgScreenReceiver
		$a_00_5 = {53 65 6e 64 53 6d 73 52 6f 6e 67 6c 69 61 6e 67 } //1 SendSmsRongliang
		$a_00_6 = {77 61 6e 2e 6d 65 69 2e 63 68 6f 6e 67 2e 64 69 61 6e 2e 71 69 } //1 wan.mei.chong.dian.qi
		$a_00_7 = {48 41 4f 77 75 70 69 6e } //1 HAOwupin
		$a_00_8 = {74 72 69 6d 5f 74 61 69 6c 5f 65 71 75 61 6c 73 69 67 6e } //1 trim_tail_equalsign
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=4
 
}