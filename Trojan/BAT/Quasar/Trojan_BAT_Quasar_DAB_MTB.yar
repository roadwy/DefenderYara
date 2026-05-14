
rule Trojan_BAT_Quasar_DAB_MTB{
	meta:
		description = "Trojan:BAT/Quasar.DAB!MTB,SIGNATURE_TYPE_PEHSTR,1c 00 1c 00 10 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 4b 65 79 6c 6f 67 67 65 72 4c 6f 67 73 44 69 72 65 63 74 6f 72 79 } //2 GetKeyloggerLogsDirectory
		$a_01_1 = {47 65 74 50 61 73 73 77 6f 72 64 73 52 65 73 70 6f 6e 73 65 } //2 GetPasswordsResponse
		$a_01_2 = {47 65 74 53 74 65 61 6c 65 72 4c 6f 67 73 } //2 GetStealerLogs
		$a_01_3 = {43 6f 6e 6e 65 63 74 52 65 76 65 72 73 65 50 72 6f 78 79 } //2 ConnectReverseProxy
		$a_01_4 = {43 68 72 6f 6d 69 75 6d 50 61 73 73 77 6f 72 64 45 78 74 65 6e 73 69 6f 6e } //2 ChromiumPasswordExtension
		$a_01_5 = {50 61 73 74 65 43 6c 69 65 6e 74 43 6c 69 70 62 6f 61 72 64 } //2 PasteClientClipboard
		$a_01_6 = {53 65 6e 64 54 6f 54 61 72 67 65 74 53 65 72 76 65 72 } //2 SendToTargetServer
		$a_01_7 = {47 65 74 52 65 76 65 72 73 65 50 72 6f 78 79 42 79 43 6f 6e 6e 65 63 74 69 6f 6e 49 64 } //2 GetReverseProxyByConnectionId
		$a_01_8 = {53 65 6e 64 48 76 6e 63 4c 6f 67 } //2 SendHvncLog
		$a_01_9 = {47 65 74 50 61 73 73 77 6f 72 64 45 78 74 65 6e 73 69 6f 6e 73 53 74 72 69 6e 67 } //2 GetPasswordExtensionsString
		$a_01_10 = {47 65 74 4b 65 79 6c 6f 67 67 65 72 4c 6f 67 73 44 69 72 65 63 74 6f 72 79 52 65 73 70 6f 6e 73 65 } //2 GetKeyloggerLogsDirectoryResponse
		$a_01_11 = {6d 00 61 00 73 00 74 00 65 00 72 00 4b 00 65 00 79 00 20 00 63 00 61 00 6e 00 20 00 6e 00 6f 00 74 00 20 00 62 00 65 00 20 00 6e 00 75 00 6c 00 6c 00 } //2 masterKey can not be null
		$a_01_12 = {44 6f 4d 6f 75 73 65 45 76 65 6e 74 } //1 DoMouseEvent
		$a_01_13 = {44 6f 53 68 75 74 64 6f 77 6e 41 63 74 69 6f 6e } //1 DoShutdownAction
		$a_01_14 = {44 6f 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 DoShellExecute
		$a_01_15 = {73 65 74 5f 63 68 72 6f 6d 69 75 6d 42 72 6f 77 73 65 72 4f 70 74 69 6f 6e 73 } //1 set_chromiumBrowserOptions
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*2+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=28
 
}