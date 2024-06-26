
rule Trojan_Win32_FakeMalean{
	meta:
		description = "Trojan:Win32/FakeMalean,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 25 00 00 14 00 "
		
	strings :
		$a_01_0 = {75 70 64 61 74 65 2d 25 64 2d 25 2e 32 64 2d 25 2e 32 64 2e 64 62 6e 2e 67 7a } //14 00  update-%d-%.2d-%.2d.dbn.gz
		$a_01_1 = {47 45 54 20 2f 75 70 64 61 74 65 2f 25 64 2f 25 64 2e 65 78 65 20 48 54 54 50 2f 31 2e 30 } //14 00  GET /update/%d/%d.exe HTTP/1.0
		$a_01_2 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 61 62 63 } //14 00  if exist "%s" goto abc
		$a_01_3 = {54 57 69 6e 64 6f 77 73 53 65 63 75 72 69 74 79 43 65 6e 74 65 72 } //0a 00  TWindowsSecurityCenter
		$a_01_4 = {4d 61 6c 77 61 72 65 20 43 6c 65 61 6e 65 72 } //0a 00  Malware Cleaner
		$a_01_5 = {6e 69 78 63 6c 65 61 6e 2e 63 6f 6d } //05 00  nixclean.com
		$a_01_6 = {68 74 74 70 3a 2f 2f 25 73 2f 68 65 6c 70 2e 70 68 70 } //05 00  http://%s/help.php
		$a_01_7 = {68 74 74 70 3a 2f 2f 25 73 2f 63 6f 6e 74 61 63 74 2e 70 68 70 } //05 00  http://%s/contact.php
		$a_01_8 = {48 6f 6d 65 42 75 74 74 6f 6e } //05 00  HomeButton
		$a_01_9 = {53 79 73 74 65 6d 53 63 61 6e 42 75 74 74 6f 6e } //05 00  SystemScanButton
		$a_01_10 = {53 65 63 75 72 69 74 79 42 75 74 74 6f 6e } //05 00  SecurityButton
		$a_01_11 = {50 72 69 76 61 63 79 42 75 74 74 6f 6e } //05 00  PrivacyButton
		$a_01_12 = {55 70 64 61 74 65 42 75 74 74 6f 6e } //05 00  UpdateButton
		$a_01_13 = {53 65 74 74 69 6e 67 73 42 75 74 74 6f 6e } //05 00  SettingsButton
		$a_01_14 = {54 72 6f 6a 61 6e 20 64 65 74 65 63 74 65 64 21 } //05 00  Trojan detected!
		$a_01_15 = {53 70 79 77 61 72 65 20 61 6c 61 72 6d 21 } //05 00  Spyware alarm!
		$a_01_16 = {50 72 69 76 61 63 79 20 69 73 20 61 74 20 72 69 73 6b 21 } //05 00  Privacy is at risk!
		$a_01_17 = {56 69 72 75 73 65 73 20 64 65 73 74 72 6f 79 65 64 21 } //05 00  Viruses destroyed!
		$a_01_18 = {54 72 6f 6a 61 6e 20 41 6c 65 72 74 21 } //01 00  Trojan Alert!
		$a_01_19 = {57 69 6e 33 32 2e 53 6d 61 6c 6c 2e 79 64 68 } //01 00  Win32.Small.ydh
		$a_01_20 = {57 69 6e 33 32 2e 41 67 65 6e 74 2e 61 68 6f 65 } //01 00  Win32.Agent.ahoe
		$a_01_21 = {4a 53 2e 41 67 65 6e 74 2e 63 72 68 } //01 00  JS.Agent.crh
		$a_01_22 = {57 69 6e 33 32 2e 4b 69 64 6f 2e 69 68 } //01 00  Win32.Kido.ih
		$a_01_23 = {57 69 6e 33 32 2e 5a 62 6f 74 2e 69 6b 68 } //01 00  Win32.Zbot.ikh
		$a_01_24 = {57 69 6e 33 32 2e 41 67 65 6e 74 2e 6d 65 65 } //01 00  Win32.Agent.mee
		$a_01_25 = {57 69 6e 33 32 2e 51 51 48 65 6c 70 65 72 2e 61 6f 63 } //01 00  Win32.QQHelper.aoc
		$a_01_26 = {57 69 6e 33 32 2e 48 75 70 69 67 6f 6e 2e 66 64 6e 76 } //01 00  Win32.Hupigon.fdnv
		$a_01_27 = {57 69 6e 33 32 2e 4b 69 64 6f 2e 66 78 } //01 00  Win32.Kido.fx
		$a_01_28 = {43 42 56 69 72 75 73 50 72 6f 74 65 63 74 69 6f 6e } //01 00  CBVirusProtection
		$a_01_29 = {43 42 53 70 79 77 61 72 65 50 72 6f 74 65 63 74 69 6f 6e } //01 00  CBSpywareProtection
		$a_01_30 = {43 42 47 65 6e 65 72 61 6c 53 65 63 75 72 69 74 79 } //01 00  CBGeneralSecurity
		$a_01_31 = {43 42 41 75 74 6f 6d 61 74 69 63 55 70 64 61 74 69 6e 67 } //01 00  CBAutomaticUpdating
		$a_01_32 = {43 42 4d 69 6e 69 6d 69 7a 65 54 6f 54 72 61 79 } //01 00  CBMinimizeToTray
		$a_01_33 = {43 42 53 74 61 72 74 57 69 74 68 57 69 6e 64 6f 77 73 } //01 00  CBStartWithWindows
		$a_01_34 = {43 42 53 63 61 6e 41 74 53 74 61 72 74 75 70 } //01 00  CBScanAtStartup
		$a_01_35 = {43 42 53 63 61 6e 69 6e 67 45 76 65 72 79 48 6f 75 72 } //01 00  CBScaningEveryHour
		$a_01_36 = {43 42 44 69 73 61 62 6c 65 53 6f 75 6e 64 73 } //00 00  CBDisableSounds
	condition:
		any of ($a_*)
 
}