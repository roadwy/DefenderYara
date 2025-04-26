
rule Trojan_BAT_Redline_CBYZ_MTB{
	meta:
		description = "Trojan:BAT/Redline.CBYZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 11 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 42 72 6f 77 73 65 72 4e 61 6d 65 } //1 get_BrowserName
		$a_01_1 = {67 65 74 5f 42 72 6f 77 73 65 72 50 72 6f 66 69 6c 65 } //1 get_BrowserProfile
		$a_01_2 = {67 65 74 5f 4c 6f 67 69 6e 73 } //1 get_Logins
		$a_01_3 = {67 65 74 5f 41 75 74 6f 66 69 6c 6c 73 } //1 get_Autofills
		$a_01_4 = {67 65 74 5f 43 6f 6f 6b 69 65 73 } //1 get_Cookies
		$a_01_5 = {67 65 74 5f 4c 6f 63 61 74 69 6f 6e } //1 get_Location
		$a_01_6 = {67 65 74 5f 50 72 6f 63 65 73 73 65 73 } //1 get_Processes
		$a_01_7 = {67 65 74 5f 53 79 73 74 65 6d 48 61 72 64 77 61 72 65 73 } //1 get_SystemHardwares
		$a_01_8 = {67 65 74 5f 46 74 70 43 6f 6e 6e 65 63 74 69 6f 6e 73 } //1 get_FtpConnections
		$a_01_9 = {67 65 74 5f 47 61 6d 65 4c 61 75 6e 63 68 65 72 46 69 6c 65 73 } //1 get_GameLauncherFiles
		$a_01_10 = {67 65 74 5f 53 63 61 6e 6e 65 64 57 61 6c 6c 65 74 73 } //1 get_ScannedWallets
		$a_01_11 = {67 65 74 5f 53 63 61 6e 54 65 6c 65 67 72 61 6d } //1 get_ScanTelegram
		$a_01_12 = {67 65 74 5f 53 63 61 6e 56 50 4e } //1 get_ScanVPN
		$a_01_13 = {67 65 74 5f 53 63 61 6e 53 74 65 61 6d } //1 get_ScanSteam
		$a_01_14 = {67 65 74 5f 53 63 61 6e 44 69 73 63 6f 72 64 } //1 get_ScanDiscord
		$a_01_15 = {67 65 74 5f 4d 61 63 68 69 6e 65 4e 61 6d 65 } //1 get_MachineName
		$a_01_16 = {67 65 74 5f 4f 53 56 65 72 73 69 6f 6e } //1 get_OSVersion
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1) >=17
 
}