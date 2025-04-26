
rule Trojan_BAT_Imminent_A_MTB{
	meta:
		description = "Trojan:BAT/Imminent.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 19 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 4d 61 6e 61 67 65 72 20 52 65 61 64 79 } //1 PluginManager Ready
		$a_01_1 = {50 6c 75 67 69 6e 50 61 63 6b 65 74 48 61 6e 64 6c 65 72 20 52 65 61 64 79 } //1 PluginPacketHandler Ready
		$a_01_2 = {43 68 61 74 20 52 65 61 64 79 } //1 Chat Ready
		$a_01_3 = {52 65 6d 6f 74 65 20 44 65 73 6b 74 6f 70 20 52 65 61 64 79 } //1 Remote Desktop Ready
		$a_01_4 = {4b 65 79 48 6f 6f 6b 20 52 65 61 64 79 } //1 KeyHook Ready
		$a_01_5 = {4b 65 79 4d 61 6e 61 67 65 72 20 52 65 61 64 79 } //1 KeyManager Ready
		$a_01_6 = {4d 69 63 72 6f 70 68 6f 6e 65 20 52 65 61 64 79 } //1 Microphone Ready
		$a_01_7 = {52 65 76 65 72 73 65 50 72 6f 78 79 20 52 65 61 64 79 } //1 ReverseProxy Ready
		$a_01_8 = {52 44 50 20 52 65 61 64 79 } //1 RDP Ready
		$a_01_9 = {52 65 6d 6f 74 65 57 65 62 63 61 6d 20 52 65 61 64 79 } //1 RemoteWebcam Ready
		$a_01_10 = {49 6e 73 74 61 6c 6c 65 72 46 6f 72 6d 20 52 65 61 64 79 } //1 InstallerForm Ready
		$a_01_11 = {43 6c 69 70 62 6f 61 72 64 4d 61 6e 61 67 65 72 20 52 65 61 64 79 } //1 ClipboardManager Ready
		$a_01_12 = {43 6f 6d 6d 61 6e 64 50 72 6f 6d 70 74 20 52 65 61 64 79 } //1 CommandPrompt Ready
		$a_01_13 = {45 78 65 63 75 74 65 55 70 64 61 74 65 4d 61 6e 61 67 65 72 20 52 65 61 64 79 } //1 ExecuteUpdateManager Ready
		$a_01_14 = {46 69 6c 65 4d 61 6e 61 67 65 72 20 52 65 61 64 79 } //1 FileManager Ready
		$a_01_15 = {46 69 6c 65 54 72 61 6e 73 66 65 72 20 52 65 61 64 79 } //1 FileTransfer Ready
		$a_01_16 = {4d 65 73 73 61 67 65 42 6f 78 20 52 65 61 64 79 } //1 MessageBox Ready
		$a_01_17 = {50 72 6f 63 65 73 73 4d 61 6e 61 67 65 72 20 52 65 61 64 79 } //1 ProcessManager Ready
		$a_01_18 = {52 65 67 69 73 74 72 79 4d 61 6e 61 67 65 72 20 52 65 61 64 79 } //1 RegistryManager Ready
		$a_01_19 = {53 63 72 69 70 74 69 6e 67 4d 61 6e 61 67 65 72 20 52 65 61 64 79 } //1 ScriptingManager Ready
		$a_01_20 = {53 69 6d 70 6c 65 54 72 61 6e 73 66 65 72 20 52 65 61 64 79 } //1 SimpleTransfer Ready
		$a_01_21 = {53 74 61 72 74 75 70 4d 61 6e 61 67 65 72 20 52 65 61 64 79 } //1 StartupManager Ready
		$a_01_22 = {54 43 50 43 6f 6e 6e 65 63 74 69 6f 6e 73 20 52 65 61 64 79 } //1 TCPConnections Ready
		$a_01_23 = {57 69 6e 64 6f 77 4d 61 6e 61 67 65 72 20 52 65 61 64 79 } //1 WindowManager Ready
		$a_01_24 = {50 61 73 73 77 6f 72 64 52 65 63 6f 76 65 72 79 20 52 65 61 64 79 } //1 PasswordRecovery Ready
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_01_24  & 1)*1) >=15
 
}