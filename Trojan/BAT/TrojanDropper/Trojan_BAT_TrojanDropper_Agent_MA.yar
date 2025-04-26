
rule Trojan_BAT_TrojanDropper_Agent_MA{
	meta:
		description = "Trojan:BAT/TrojanDropper.Agent.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 71 31 32 31 32 2e 6d 65 2f 56 76 2f } //1 http://q1212.me/Vv/
		$a_81_1 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //1 Form1_Load
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_81_3 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_81_4 = {53 6c 65 65 70 } //1 Sleep
		$a_81_5 = {73 74 6f 70 20 73 76 63 68 6f 73 74 } //1 stop svchost
		$a_81_6 = {55 70 6c 6f 61 64 53 74 72 69 6e 67 } //1 UploadString
		$a_81_7 = {57 4d 5f 4b 45 59 44 4f 57 4e } //1 WM_KEYDOWN
		$a_81_8 = {67 65 74 5f 4d 61 63 68 69 6e 65 4e 61 6d 65 } //1 get_MachineName
		$a_81_9 = {47 65 74 48 6f 73 74 4e 61 6d 65 } //1 GetHostName
		$a_81_10 = {74 78 74 68 69 73 74 6f 72 79 } //1 txthistory
		$a_81_11 = {49 50 48 6f 73 74 45 6e 74 72 79 } //1 IPHostEntry
		$a_81_12 = {47 65 74 48 6f 73 74 45 6e 74 72 79 } //1 GetHostEntry
		$a_81_13 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=14
 
}