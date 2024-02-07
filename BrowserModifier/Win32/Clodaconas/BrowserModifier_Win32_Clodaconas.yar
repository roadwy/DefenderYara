
rule BrowserModifier_Win32_Clodaconas{
	meta:
		description = "BrowserModifier:Win32/Clodaconas,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 64 6c 6c } //01 00  ConsoleApplication1.dll
		$a_01_1 = {67 65 74 48 65 78 53 74 72 75 } //01 00  getHexStru
		$a_01_2 = {67 65 74 4d 64 35 4a 73 6f 6e 75 } //01 00  getMd5Jsonu
		$a_01_3 = {67 65 74 4d 64 35 75 } //01 00  getMd5u
		$a_01_4 = {67 65 74 55 69 64 75 } //01 00  getUidu
		$a_01_5 = {69 73 56 4d 33 } //01 00  isVM3
		$a_01_6 = {69 73 56 4d 34 } //01 00  isVM4
		$a_01_7 = {70 72 65 69 6e 73 74 61 6c 6c } //01 00  preinstall
		$a_01_8 = {73 65 6e 64 50 69 6e 67 47 65 74 } //01 00  sendPingGet
		$a_01_9 = {73 65 6e 64 50 69 6e 67 4a 73 6f 6e 55 } //01 00  sendPingJsonU
		$a_01_10 = {73 65 6e 64 50 69 6e 67 54 6f 6f 47 65 74 } //01 00  sendPingTooGet
		$a_01_11 = {75 6e 69 6e 73 74 61 6c 6c 46 78 } //00 00  uninstallFx
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Clodaconas_2{
	meta:
		description = "BrowserModifier:Win32/Clodaconas,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 00 63 00 6f 00 6e 00 73 00 2f 00 63 00 6c 00 6f 00 75 00 64 00 67 00 75 00 61 00 72 00 64 00 2e 00 69 00 63 00 6f 00 } //02 00  icons/cloudguard.ico
		$a_01_1 = {6e 71 35 6e 38 68 70 62 73 6d 77 7a 63 73 65 62 35 76 63 70 76 62 74 6c 61 75 35 6a 75 6c 62 38 } //01 00  nq5n8hpbsmwzcseb5vcpvbtlau5julb8
		$a_01_2 = {49 31 69 49 69 6c 31 49 6c 31 49 49 } //01 00  I1iIil1Il1II
		$a_01_3 = {68 66 58 50 6c 6f 72 65 72 42 61 72 } //02 00  hfXPlorerBar
		$a_01_4 = {47 72 65 65 6e 54 65 61 6d 44 4e 53 2e 41 70 70 } //01 00  GreenTeamDNS.App
		$a_01_5 = {35 00 64 00 61 00 30 00 35 00 39 00 61 00 34 00 38 00 32 00 66 00 64 00 34 00 39 00 34 00 64 00 62 00 33 00 66 00 32 00 35 00 32 00 31 00 32 00 36 00 66 00 62 00 63 00 33 00 64 00 35 00 62 00 } //00 00  5da059a482fd494db3f252126fbc3d5b
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Clodaconas_3{
	meta:
		description = "BrowserModifier:Win32/Clodaconas,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 50 69 6e 67 54 6f 6f } //01 00  sendPingToo
		$a_01_1 = {4d 69 73 73 69 6e 67 20 47 65 6e 65 72 61 6c 20 45 58 45 4c 61 62 65 6c } //01 00  Missing General EXELabel
		$a_01_2 = {50 6f 73 74 70 6f 6e 65 45 58 45 4c 61 62 65 6c } //01 00  PostponeEXELabel
		$a_01_3 = {44 69 64 6e 27 74 20 6b 69 6c 6c 2e } //01 00  Didn't kill.
		$a_01_4 = {44 68 63 70 4e 6f 74 69 66 79 43 6f 6e 66 69 67 43 68 61 6e 67 65 } //01 00  DhcpNotifyConfigChange
		$a_00_5 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 35 00 64 00 61 00 30 00 35 00 39 00 61 00 34 00 38 00 32 00 66 00 64 00 34 00 39 00 34 00 64 00 62 00 33 00 66 00 32 00 35 00 32 00 31 00 32 00 36 00 66 00 62 00 63 00 33 00 64 00 35 00 62 00 } //01 00  SOFTWARE\5da059a482fd494db3f252126fbc3d5b
		$a_01_6 = {53 00 65 00 74 00 2d 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 3a 00 5c 00 62 00 2a 00 7b 00 2e 00 2b 00 3f 00 7d 00 5c 00 6e 00 } //01 00  Set-Cookie:\b*{.+?}\n
		$a_01_7 = {4c 00 6f 00 63 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 20 00 7b 00 5b 00 30 00 2d 00 39 00 5d 00 2b 00 7d 00 } //01 00  Location: {[0-9]+}
		$a_01_8 = {30 30 3a 30 35 3a 36 39 } //01 00  00:05:69
		$a_01_9 = {30 30 3a 30 43 3a 32 39 } //00 00  00:0C:29
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Clodaconas_4{
	meta:
		description = "BrowserModifier:Win32/Clodaconas,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 00 63 00 6f 00 6e 00 73 00 2f 00 63 00 6c 00 6f 00 75 00 64 00 67 00 75 00 61 00 72 00 64 00 2e 00 69 00 63 00 6f 00 } //02 00  icons/cloudguard.ico
		$a_01_1 = {6e 71 35 6e 38 68 70 62 73 6d 77 7a 63 73 65 62 35 76 63 70 76 62 74 6c 61 75 35 6a 75 6c 62 38 } //01 00  nq5n8hpbsmwzcseb5vcpvbtlau5julb8
		$a_01_2 = {49 31 69 49 69 6c 31 49 6c 31 49 49 } //01 00  I1iIil1Il1II
		$a_01_3 = {35 00 64 00 61 00 30 00 35 00 39 00 61 00 34 00 38 00 32 00 66 00 64 00 34 00 39 00 34 00 64 00 62 00 33 00 66 00 32 00 35 00 32 00 31 00 32 00 36 00 66 00 62 00 63 00 33 00 64 00 35 00 62 00 } //01 00  5da059a482fd494db3f252126fbc3d5b
		$a_01_4 = {51 41 6c 74 65 72 6e 61 74 69 76 65 20 74 6f 20 61 20 66 75 6c 6c 79 20 62 6c 6f 77 6e 20 54 6f 6f 6c 54 69 70 } //01 00  QAlternative to a fully blown ToolTip
		$a_01_5 = {31 66 31 36 38 33 39 36 30 31 61 61 34 30 36 66 38 61 35 34 33 33 65 66 39 36 36 35 64 39 37 31 } //01 00  1f16839601aa406f8a5433ef9665d971
		$a_01_6 = {53 65 74 52 6f 6f 74 43 65 72 74 69 66 69 63 61 74 65 } //01 00  SetRootCertificate
		$a_01_7 = {47 72 65 65 6e 54 65 61 6d 5c 77 70 66 2d 6e 6f 74 69 66 79 69 63 6f 6e 5c 57 69 6e 64 6f 77 6c 65 73 73 20 53 61 6d 70 6c 65 } //01 00  GreenTeam\wpf-notifyicon\Windowless Sample
		$a_01_8 = {4d 00 62 00 62 00 44 00 61 00 6c 00 69 00 47 00 73 00 6d 00 44 00 65 00 76 00 69 00 63 00 65 00 20 00 53 00 65 00 74 00 44 00 6e 00 73 00 20 00 3a 00 20 00 41 00 6e 00 20 00 65 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00 20 00 6f 00 63 00 63 00 75 00 72 00 72 00 65 00 64 00 20 00 77 00 68 00 69 00 6c 00 65 00 20 00 74 00 72 00 79 00 69 00 6e 00 67 00 20 00 74 00 6f 00 20 00 73 00 65 00 74 00 20 00 74 00 68 00 65 00 20 00 44 00 4e 00 53 00 3a 00 } //00 00  MbbDaliGsmDevice SetDns : An exception occurred while trying to set the DNS:
	condition:
		any of ($a_*)
 
}