
rule TrojanSpy_Win32_Winspy_Z{
	meta:
		description = "TrojanSpy:Win32/Winspy.Z,SIGNATURE_TYPE_PEHSTR_EXT,19 00 14 00 15 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 6f 64 41 75 74 6f 43 6c 65 61 6e } //01 00  modAutoClean
		$a_01_1 = {6d 6f 64 43 68 65 63 6b 52 75 6e 6e 69 6e 67 50 72 6f 63 65 73 73 } //01 00  modCheckRunningProcess
		$a_01_2 = {6d 6f 64 53 63 72 65 65 6e 43 61 70 74 75 72 65 } //01 00  modScreenCapture
		$a_01_3 = {6d 6f 67 47 65 74 4f 53 } //01 00  mogGetOS
		$a_01_4 = {6d 6f 64 41 6e 74 69 53 70 79 } //01 00  modAntiSpy
		$a_01_5 = {6d 64 6d 56 46 72 61 6d 65 } //01 00  mdmVFrame
		$a_01_6 = {63 6c 56 43 61 70 74 75 72 65 } //01 00  clVCapture
		$a_01_7 = {6d 6f 64 69 6e 69 66 69 6c 65 64 65 61 64 } //01 00  modinifiledead
		$a_01_8 = {63 6c 73 55 52 4c 4d 6f 6e } //01 00  clsURLMon
		$a_01_9 = {74 6d 72 53 74 61 72 74 43 61 6d } //01 00  tmrStartCam
		$a_01_10 = {63 6d 64 54 65 73 74 53 4d 54 50 } //01 00  cmdTestSMTP
		$a_01_11 = {74 78 74 45 6d 61 69 6c 49 6e 74 65 72 76 61 6c } //01 00  txtEmailInterval
		$a_01_12 = {63 6d 64 45 6e 61 62 6c 65 57 61 74 63 68 } //01 00  cmdEnableWatch
		$a_01_13 = {74 6d 72 4f 6e 6c 69 6e 65 54 69 6d 65 33 } //02 00  tmrOnlineTime3
		$a_01_14 = {43 68 65 63 6b 52 75 6e 6e 69 6e 67 50 72 6f 63 65 73 73 5f 4f 55 54 4c 4f 4f 4b } //02 00  CheckRunningProcess_OUTLOOK
		$a_01_15 = {43 68 65 63 6b 52 75 6e 6e 69 6e 67 50 72 6f 63 65 73 73 5f 49 45 58 50 4c 4f 52 45 } //07 00  CheckRunningProcess_IEXPLORE
		$a_01_16 = {5c 00 52 00 65 00 6e 00 6f 00 4e 00 65 00 76 00 61 00 64 00 61 00 5c 00 4d 00 61 00 69 00 6e 00 4d 00 61 00 6e 00 67 00 6f 00 5c 00 53 00 65 00 72 00 76 00 65 00 72 00 2e 00 76 00 62 00 70 00 } //02 00  \RenoNevada\MainMango\Server.vbp
		$a_01_17 = {55 00 6e 00 68 00 69 00 64 00 65 00 20 00 46 00 6f 00 6c 00 64 00 65 00 72 00 } //05 00  Unhide Folder
		$a_01_18 = {6e 00 65 00 74 00 20 00 6c 00 6f 00 63 00 61 00 6c 00 67 00 72 00 6f 00 75 00 70 00 20 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 73 00 20 00 2f 00 41 00 64 00 64 00 20 00 } //03 00  net localgroup Administrators /Add 
		$a_01_19 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 77 00 69 00 6e 00 2d 00 73 00 70 00 79 00 2e 00 63 00 6f 00 6d 00 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 } //04 00  http://www.win-spy.com/update
		$a_01_20 = {5c 00 54 00 65 00 6d 00 70 00 5c 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 2e 00 65 00 78 00 65 00 20 00 2f 00 75 00 } //00 00  \Temp\desktop.exe /u
	condition:
		any of ($a_*)
 
}