
rule TrojanDownloader_Win32_Agent_IS{
	meta:
		description = "TrojanDownloader:Win32/Agent.IS,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 13 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 73 76 70 2e 65 78 65 } //01 00  rsvp.exe
		$a_01_1 = {5c 4c 4f 43 41 4c 53 7e 31 5c 41 50 50 4c 49 43 7e 31 5c 4d 49 43 52 4f 53 7e 31 5c } //01 00  \LOCALS~1\APPLIC~1\MICROS~1\
		$a_01_2 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //01 00  CreateMutexA
		$a_01_3 = {65 73 65 6e 74 75 74 6c 2e 65 78 65 } //01 00  esentutl.exe
		$a_01_4 = {52 65 67 47 65 74 4b 65 79 53 65 63 75 72 69 74 79 } //01 00  RegGetKeySecurity
		$a_01_5 = {63 69 73 76 63 2e 65 78 65 } //01 00  cisvc.exe
		$a_01_6 = {6d 71 74 67 73 76 63 2e 65 78 65 } //01 00  mqtgsvc.exe
		$a_01_7 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //01 00  InternetOpenUrlA
		$a_01_8 = {69 65 75 64 69 6e 69 74 2e 65 78 65 } //01 00  ieudinit.exe
		$a_01_9 = {64 6c 6c 68 73 74 33 67 2e 65 78 65 } //01 00  dllhst3g.exe
		$a_01_10 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
		$a_01_11 = {63 6c 69 70 73 72 76 2e 65 78 65 } //01 00  clipsrv.exe
		$a_01_12 = {73 65 73 73 6d 67 72 2e 65 78 65 } //01 00  sessmgr.exe
		$a_01_13 = {6d 73 74 69 6e 69 74 2e 65 78 65 } //01 00  mstinit.exe
		$a_01_14 = {63 6f 6d 72 65 70 6c 2e 65 78 65 } //01 00  comrepl.exe
		$a_01_15 = {6c 6f 67 6d 61 6e 2e 65 78 65 } //01 00  logman.exe
		$a_01_16 = {63 6d 73 74 70 2e 65 78 65 } //01 00  cmstp.exe
		$a_01_17 = {34 30 32 44 41 37 46 33 2d 46 46 41 45 2d 38 33 42 45 2d 46 31 33 33 2d 45 41 36 32 42 34 34 45 41 43 41 35 } //01 00  402DA7F3-FFAE-83BE-F133-EA62B44EACA5
		$a_01_18 = {73 70 6f 6f 6c 73 76 2e 65 78 65 } //00 00  spoolsv.exe
	condition:
		any of ($a_*)
 
}