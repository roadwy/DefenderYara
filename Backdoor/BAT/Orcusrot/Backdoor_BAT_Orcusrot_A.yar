
rule Backdoor_BAT_Orcusrot_A{
	meta:
		description = "Backdoor:BAT/Orcusrot.A,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 1a 00 00 "
		
	strings :
		$a_01_0 = {44 44 6f 53 43 6f 6d 6d 75 6e 69 63 61 74 69 6f 6e } //1 DDoSCommunication
		$a_01_1 = {48 74 74 70 46 6c 6f 6f 64 } //1 HttpFlood
		$a_01_2 = {49 63 6d 70 46 6c 6f 6f 64 } //1 IcmpFlood
		$a_01_3 = {53 79 6e 46 6c 6f 6f 64 } //1 SynFlood
		$a_01_4 = {55 64 70 46 6c 6f 6f 64 } //1 UdpFlood
		$a_01_5 = {52 65 73 70 6f 6e 73 65 41 74 74 61 63 6b 4f 70 65 6e } //1 ResponseAttackOpen
		$a_01_6 = {53 75 62 6d 69 74 4b 65 79 6c 6f 67 73 } //1 SubmitKeylogs
		$a_01_7 = {47 65 74 4b 65 79 4c 6f 67 } //1 GetKeyLog
		$a_01_8 = {47 65 74 50 61 73 73 77 6f 72 64 } //1 GetPassword
		$a_01_9 = {52 65 63 6f 76 65 72 65 64 43 6f 6f 6b 69 65 } //1 RecoveredCookie
		$a_01_10 = {52 65 63 6f 76 65 72 65 64 50 61 73 73 77 6f 72 64 } //1 RecoveredPassword
		$a_01_11 = {55 70 64 61 74 65 46 72 6f 6d 55 72 6c } //1 UpdateFromUrl
		$a_01_12 = {47 65 74 57 65 62 63 61 6d } //1 GetWebcam
		$a_01_13 = {52 65 76 65 72 73 65 50 72 6f 78 79 } //1 ReverseProxy
		$a_01_14 = {52 65 6d 6f 74 65 44 65 73 6b 74 6f 70 43 6f 6d 6d 75 6e 69 63 61 74 69 6f 6e } //1 RemoteDesktopCommunication
		$a_01_15 = {53 74 61 72 74 4d 61 73 73 44 6f 77 6e 6c 6f 61 64 } //1 StartMassDownload
		$a_01_16 = {44 6f 77 6e 6c 6f 61 64 41 6e 64 4f 70 65 6e 46 69 6c 65 } //1 DownloadAndOpenFile
		$a_01_17 = {44 69 73 61 62 6c 65 4d 6f 6e 69 74 6f 72 } //1 DisableMonitor
		$a_01_18 = {44 69 73 61 62 6c 65 54 61 73 6b 6d 61 6e 61 67 65 72 } //1 DisableTaskmanager
		$a_01_19 = {44 69 73 61 62 6c 65 55 73 65 72 49 6e 70 75 74 } //1 DisableUserInput
		$a_01_20 = {48 61 6e 67 53 79 73 74 65 6d } //1 HangSystem
		$a_01_21 = {48 69 64 65 54 61 73 6b 62 61 72 } //1 HideTaskbar
		$a_01_22 = {48 69 64 64 65 6e 53 74 61 72 74 } //1 HiddenStart
		$a_01_23 = {41 6e 74 69 44 65 62 75 67 67 65 72 } //1 AntiDebugger
		$a_01_24 = {41 6e 74 69 54 63 70 41 6e 61 6c 79 7a 65 72 } //1 AntiTcpAnalyzer
		$a_01_25 = {50 72 6f 74 65 63 74 46 72 6f 6d 56 4d 73 } //1 ProtectFromVMs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_01_24  & 1)*1+(#a_01_25  & 1)*1) >=20
 
}