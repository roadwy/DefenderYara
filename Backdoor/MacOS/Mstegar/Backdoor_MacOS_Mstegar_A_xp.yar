
rule Backdoor_MacOS_Mstegar_A_xp{
	meta:
		description = "Backdoor:MacOS/Mstegar.A!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {55 70 6c 6f 61 64 54 6f 52 65 6d 6f 74 65 } //1 UploadToRemote
		$a_00_1 = {4d 6f 6e 69 74 6f 72 54 68 72 65 61 64 } //1 MonitorThread
		$a_00_2 = {2f 41 70 70 6c 69 63 61 74 69 6f 6e 73 2f 55 70 64 61 74 65 2e 61 70 70 } //1 /Applications/Update.app
		$a_00_3 = {2f 53 74 61 72 74 75 70 50 61 72 61 6d 65 74 65 72 73 2e 70 6c 69 73 74 } //1 /StartupParameters.plist
		$a_00_4 = {41 75 74 6f 4c 61 75 6e 63 68 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 44 69 63 74 69 6f 6e 61 72 79 } //1 AutoLaunchedApplicationDictionary
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}