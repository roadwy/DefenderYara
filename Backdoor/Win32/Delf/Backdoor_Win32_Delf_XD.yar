
rule Backdoor_Win32_Delf_XD{
	meta:
		description = "Backdoor:Win32/Delf.XD,SIGNATURE_TYPE_PEHSTR_EXT,ffffffca 01 ffffffc4 01 13 00 00 32 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //32 00  SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {4b 61 69 73 6f 66 74 20 48 54 54 50 47 65 74 } //32 00  Kaisoft HTTPGet
		$a_00_2 = {53 00 6f 00 63 00 6b 00 65 00 74 00 20 00 69 00 73 00 20 00 61 00 6c 00 72 00 65 00 61 00 64 00 79 00 20 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 65 00 64 00 } //32 00  Socket is already connected
		$a_00_3 = {54 49 64 54 43 50 43 6c 69 65 6e 74 } //32 00  TIdTCPClient
		$a_00_4 = {52 65 63 65 69 76 65 20 6d 65 73 73 61 67 65 20 66 72 6f 6d 20 72 65 6d 6f 74 65 } //32 00  Receive message from remote
		$a_00_5 = {48 74 74 70 50 72 6f 78 79 } //32 00  HttpProxy
		$a_01_6 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //32 00  InternetReadFile
		$a_01_7 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //32 00  HttpSendRequestA
		$a_00_8 = {46 74 70 50 75 74 46 69 6c 65 41 } //01 00  FtpPutFileA
		$a_00_9 = {61 75 74 6f 72 75 6e 73 2e 65 78 65 } //01 00  autoruns.exe
		$a_00_10 = {70 72 6f 63 65 78 70 2e 65 78 65 } //01 00  procexp.exe
		$a_00_11 = {4b 61 76 50 46 57 2e 45 58 45 } //01 00  KavPFW.EXE
		$a_00_12 = {4b 50 46 57 33 32 2e 45 58 45 } //01 00  KPFW32.EXE
		$a_00_13 = {50 46 57 2e 65 78 65 } //01 00  PFW.exe
		$a_00_14 = {53 79 73 53 61 66 65 2e 65 78 65 } //01 00  SysSafe.exe
		$a_00_15 = {46 69 72 65 57 61 6c 6c 2e 65 78 65 } //01 00  FireWall.exe
		$a_00_16 = {4d 63 41 66 65 65 46 69 72 65 2e 65 78 65 } //01 00  McAfeeFire.exe
		$a_00_17 = {46 69 72 65 54 72 61 79 2e 65 78 65 } //01 00  FireTray.exe
		$a_00_18 = {5a 6f 6e 65 41 6c 61 72 6d } //00 00  ZoneAlarm
	condition:
		any of ($a_*)
 
}