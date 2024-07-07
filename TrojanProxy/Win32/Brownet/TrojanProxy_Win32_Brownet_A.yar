
rule TrojanProxy_Win32_Brownet_A{
	meta:
		description = "TrojanProxy:Win32/Brownet.A,SIGNATURE_TYPE_PEHSTR,10 00 0e 00 14 00 00 "
		
	strings :
		$a_01_0 = {42 72 6f 77 6e 69 65 5f 42 72 6f 77 6e 69 65 53 65 72 76 69 63 65 5f } //8 Brownie_BrownieService_
		$a_01_1 = {50 4f 50 48 61 63 6b } //2 POPHack
		$a_01_2 = {47 65 74 42 72 6f 77 6e 69 65 43 6f 6d 70 6f 6e 65 6e 74 73 } //2 GetBrownieComponents
		$a_01_3 = {47 65 74 53 75 70 65 72 57 65 62 42 72 6f 77 73 65 72 } //2 GetSuperWebBrowser
		$a_01_4 = {43 61 70 74 63 68 61 57 6f 72 6b 65 72 } //1 CaptchaWorker
		$a_01_5 = {48 6f 74 6d 61 69 6c 57 6f 72 6b 65 72 } //1 HotmailWorker
		$a_01_6 = {4d 61 69 6c 54 61 73 6b 57 6f 72 6b 65 72 } //1 MailTaskWorker
		$a_01_7 = {47 6d 61 69 6c 57 6f 72 6b 65 72 } //1 GmailWorker
		$a_01_8 = {44 65 61 74 68 42 79 43 61 70 74 63 68 61 } //1 DeathByCaptcha
		$a_01_9 = {49 6e 74 65 72 6e 61 6c 42 72 6f 77 6e 69 65 77 57 6f 72 6b 65 72 } //1 InternalBrowniewWorker
		$a_01_10 = {43 72 61 69 67 73 6c 69 73 74 54 61 73 6b 57 6f 72 6b 65 72 } //1 CraigslistTaskWorker
		$a_01_11 = {53 65 74 41 64 64 65 64 54 69 63 6b 65 74 6d 61 73 74 65 72 54 61 73 6b 43 6f 6d 70 6c 65 74 65 64 } //1 SetAddedTicketmasterTaskCompleted
		$a_01_12 = {53 65 6e 64 42 6f 74 53 74 61 74 75 73 43 6f 6d 70 6c 65 74 65 64 } //1 SendBotStatusCompleted
		$a_01_13 = {42 6f 74 4b 6e 6f 63 6b 43 6f 6d 70 6c 65 74 65 64 } //1 BotKnockCompleted
		$a_01_14 = {43 6f 75 6e 74 44 65 61 64 42 6f 74 73 } //1 CountDeadBots
		$a_01_15 = {43 6f 75 6e 74 45 78 65 63 75 74 65 42 6f 74 73 53 70 65 63 69 66 69 65 64 } //1 CountExecuteBotsSpecified
		$a_01_16 = {43 6f 75 6e 74 4f 6e 6c 69 6e 65 42 6f 74 73 53 70 65 63 69 66 69 65 64 } //1 CountOnlineBotsSpecified
		$a_01_17 = {43 6f 75 6e 74 44 65 61 64 42 6f 74 73 53 70 65 63 69 66 69 65 64 } //1 CountDeadBotsSpecified
		$a_01_18 = {43 6f 75 6e 74 41 6c 6c 42 6f 74 73 53 70 65 63 69 66 69 65 64 } //1 CountAllBotsSpecified
		$a_01_19 = {53 65 6e 64 43 72 61 69 67 73 6c 69 73 74 43 72 65 61 74 65 41 63 63 6f 75 6e 74 52 65 71 75 65 73 74 } //1 SendCraigslistCreateAccountRequest
	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1) >=14
 
}