
rule TrojanSpy_Win32_Winspy_Z{
	meta:
		description = "TrojanSpy:Win32/Winspy.Z,SIGNATURE_TYPE_PEHSTR_EXT,19 00 14 00 15 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 64 41 75 74 6f 43 6c 65 61 6e } //1 modAutoClean
		$a_01_1 = {6d 6f 64 43 68 65 63 6b 52 75 6e 6e 69 6e 67 50 72 6f 63 65 73 73 } //1 modCheckRunningProcess
		$a_01_2 = {6d 6f 64 53 63 72 65 65 6e 43 61 70 74 75 72 65 } //1 modScreenCapture
		$a_01_3 = {6d 6f 67 47 65 74 4f 53 } //1 mogGetOS
		$a_01_4 = {6d 6f 64 41 6e 74 69 53 70 79 } //1 modAntiSpy
		$a_01_5 = {6d 64 6d 56 46 72 61 6d 65 } //1 mdmVFrame
		$a_01_6 = {63 6c 56 43 61 70 74 75 72 65 } //1 clVCapture
		$a_01_7 = {6d 6f 64 69 6e 69 66 69 6c 65 64 65 61 64 } //1 modinifiledead
		$a_01_8 = {63 6c 73 55 52 4c 4d 6f 6e } //1 clsURLMon
		$a_01_9 = {74 6d 72 53 74 61 72 74 43 61 6d } //1 tmrStartCam
		$a_01_10 = {63 6d 64 54 65 73 74 53 4d 54 50 } //1 cmdTestSMTP
		$a_01_11 = {74 78 74 45 6d 61 69 6c 49 6e 74 65 72 76 61 6c } //1 txtEmailInterval
		$a_01_12 = {63 6d 64 45 6e 61 62 6c 65 57 61 74 63 68 } //1 cmdEnableWatch
		$a_01_13 = {74 6d 72 4f 6e 6c 69 6e 65 54 69 6d 65 33 } //1 tmrOnlineTime3
		$a_01_14 = {43 68 65 63 6b 52 75 6e 6e 69 6e 67 50 72 6f 63 65 73 73 5f 4f 55 54 4c 4f 4f 4b } //2 CheckRunningProcess_OUTLOOK
		$a_01_15 = {43 68 65 63 6b 52 75 6e 6e 69 6e 67 50 72 6f 63 65 73 73 5f 49 45 58 50 4c 4f 52 45 } //2 CheckRunningProcess_IEXPLORE
		$a_01_16 = {5c 00 52 00 65 00 6e 00 6f 00 4e 00 65 00 76 00 61 00 64 00 61 00 5c 00 4d 00 61 00 69 00 6e 00 4d 00 61 00 6e 00 67 00 6f 00 5c 00 53 00 65 00 72 00 76 00 65 00 72 00 2e 00 76 00 62 00 70 00 } //7 \RenoNevada\MainMango\Server.vbp
		$a_01_17 = {55 00 6e 00 68 00 69 00 64 00 65 00 20 00 46 00 6f 00 6c 00 64 00 65 00 72 00 } //2 Unhide Folder
		$a_01_18 = {6e 00 65 00 74 00 20 00 6c 00 6f 00 63 00 61 00 6c 00 67 00 72 00 6f 00 75 00 70 00 20 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 73 00 20 00 2f 00 41 00 64 00 64 00 20 00 } //5 net localgroup Administrators /Add 
		$a_01_19 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 77 00 69 00 6e 00 2d 00 73 00 70 00 79 00 2e 00 63 00 6f 00 6d 00 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 } //3 http://www.win-spy.com/update
		$a_01_20 = {5c 00 54 00 65 00 6d 00 70 00 5c 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 2e 00 65 00 78 00 65 00 20 00 2f 00 75 00 } //4 \Temp\desktop.exe /u
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*2+(#a_01_15  & 1)*2+(#a_01_16  & 1)*7+(#a_01_17  & 1)*2+(#a_01_18  & 1)*5+(#a_01_19  & 1)*3+(#a_01_20  & 1)*4) >=20
 
}