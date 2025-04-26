
rule Trojan_BAT_AsyncRAT_A_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.A!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {43 6c 69 65 6e 74 2e 4d 6f 64 75 6c 65 73 2e 4b 65 79 6c 6f 67 67 65 72 } //1 Client.Modules.Keylogger
		$a_01_1 = {53 65 6e 64 4b 65 79 4c 6f 67 73 } //1 SendKeyLogs
		$a_01_2 = {43 6c 69 65 6e 74 2e 4d 6f 64 75 6c 65 73 2e 43 6c 69 70 70 65 72 } //1 Client.Modules.Clipper
		$a_01_3 = {43 6c 69 70 62 6f 61 72 64 54 65 78 74 } //1 ClipboardText
		$a_01_4 = {2e 54 61 72 67 65 74 73 2e 42 72 6f 77 73 65 72 73 } //1 .Targets.Browsers
		$a_01_5 = {44 65 74 65 63 74 43 72 65 64 69 74 43 61 72 64 54 79 70 65 } //1 DetectCreditCardType
		$a_01_6 = {44 69 73 63 6f 72 64 } //1 Discord
		$a_01_7 = {50 61 73 73 77 6f 72 64 73 2e 54 61 72 67 65 74 73 2e 53 79 73 74 65 6d } //1 Passwords.Targets.System
		$a_01_8 = {47 65 74 50 72 6f 66 69 6c 65 73 } //1 GetProfiles
		$a_01_9 = {75 70 6c 6f 61 64 66 69 6c 65 } //1 uploadfile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}