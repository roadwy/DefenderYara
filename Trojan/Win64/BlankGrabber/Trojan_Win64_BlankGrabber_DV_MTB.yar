
rule Trojan_Win64_BlankGrabber_DV_MTB{
	meta:
		description = "Trojan:Win64/BlankGrabber.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 16 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 6c 61 6e 6b 47 72 61 62 62 65 72 } //01 00  BlankGrabber
		$a_01_1 = {2e 53 74 65 61 6c 4d 69 6e 65 63 72 61 66 74 } //01 00  .StealMinecraft
		$a_01_2 = {2e 53 74 65 61 6c 47 72 6f 77 74 6f 70 69 61 } //01 00  .StealGrowtopia
		$a_01_3 = {53 74 65 61 6c 69 6e 67 20 53 74 65 61 6d 20 73 65 73 73 69 6f 6e } //01 00  Stealing Steam session
		$a_01_4 = {2e 53 74 65 61 6c 55 70 6c 61 79 } //01 00  .StealUplay
		$a_01_5 = {2e 53 74 65 61 6c 52 6f 62 6c 6f 78 43 6f 6f 6b 69 65 73 } //01 00  .StealRobloxCookies
		$a_01_6 = {2e 53 74 65 61 6c 57 61 6c 6c 65 74 73 } //01 00  .StealWallets
		$a_01_7 = {2e 53 74 65 61 6c 53 79 73 74 65 6d 49 6e 66 6f } //01 00  .StealSystemInfo
		$a_01_8 = {2e 47 65 74 44 69 72 65 63 74 6f 72 79 54 72 65 65 } //01 00  .GetDirectoryTree
		$a_01_9 = {70 6f 77 65 72 73 68 65 6c 6c 20 47 65 74 2d 43 6c 69 70 62 6f 61 72 64 } //01 00  powershell Get-Clipboard
		$a_01_10 = {2e 47 65 74 41 6e 74 69 76 69 72 75 73 } //01 00  .GetAntivirus
		$a_01_11 = {2e 47 65 74 54 61 73 6b 4c 69 73 74 } //01 00  .GetTaskList
		$a_01_12 = {2e 47 65 74 57 69 66 69 50 61 73 73 77 6f 72 64 73 } //01 00  .GetWifiPasswords
		$a_01_13 = {2e 54 61 6b 65 53 63 72 65 65 6e 73 68 6f 74 } //01 00  .TakeScreenshot
		$a_01_14 = {42 6c 6f 63 6b 69 6e 67 20 41 56 20 73 69 74 65 73 } //01 00  Blocking AV sites
		$a_01_15 = {72 65 67 20 64 65 6c 65 74 65 20 68 6b 63 75 5c 53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 6d 73 2d 73 65 74 74 69 6e 67 73 20 2f 66 } //01 00  reg delete hkcu\Software\Classes\ms-settings /f
		$a_01_16 = {70 69 6e 67 20 6c 6f 63 61 6c 68 6f 73 74 20 2d 6e 20 33 20 3e 20 4e 55 4c 20 26 26 20 64 65 6c 20 2f 41 20 48 20 2f 46 20 22 7b 7d 22 } //01 00  ping localhost -n 3 > NUL && del /A H /F "{}"
		$a_01_17 = {44 69 73 63 6f 72 64 2e 47 65 74 54 6f 6b 65 6e 73 } //01 00  Discord.GetTokens
		$a_01_18 = {65 6a 62 61 6c 62 61 6b 6f 70 6c 63 68 6c 67 68 65 63 64 61 6c 6d 65 65 65 61 6a 6e 69 6d 68 6d } //01 00  ejbalbakoplchlghecdalmeeeajnimhm
		$a_01_19 = {6e 6b 62 69 68 66 62 65 6f 67 61 65 61 6f 65 68 6c 65 66 6e 6b 6f 64 62 65 66 67 70 67 6b 6e 6e } //01 00  nkbihfbeogaeaoehlefnkodbefgpgknn
		$a_01_20 = {2e 53 74 65 61 6c 42 72 6f 77 73 65 72 44 61 74 61 2e 3c 6c 6f 63 61 6c 73 3e 2e 72 75 6e } //01 00  .StealBrowserData.<locals>.run
		$a_01_21 = {2e 53 74 65 61 6c 54 65 6c 65 67 72 61 6d 53 65 73 73 69 6f 6e 73 } //00 00  .StealTelegramSessions
	condition:
		any of ($a_*)
 
}