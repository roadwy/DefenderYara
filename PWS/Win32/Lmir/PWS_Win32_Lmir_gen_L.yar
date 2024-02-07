
rule PWS_Win32_Lmir_gen_L{
	meta:
		description = "PWS:Win32/Lmir.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,ffffffaa 00 ffffffa0 00 18 00 00 19 00 "
		
	strings :
		$a_00_0 = {52 61 76 4d 6f 6e 2e 65 78 65 } //19 00  RavMon.exe
		$a_00_1 = {5a 6f 6e 65 41 6c 61 72 6d } //19 00  ZoneAlarm
		$a_00_2 = {5a 41 46 72 61 6d 65 57 6e 64 } //19 00  ZAFrameWnd
		$a_00_3 = {45 47 48 4f 53 54 2e 45 58 45 } //19 00  EGHOST.EXE
		$a_00_4 = {4d 41 49 4c 4d 4f 4e 2e 45 58 45 } //19 00  MAILMON.EXE
		$a_00_5 = {6e 65 74 62 61 72 67 70 2e 65 78 65 } //19 00  netbargp.exe
		$a_00_6 = {76 72 76 6d 6f 6e 2e 45 58 45 } //05 00  vrvmon.EXE
		$a_00_7 = {50 46 57 2e 45 58 45 } //05 00  PFW.EXE
		$a_00_8 = {4b 41 56 50 46 57 2e 45 58 45 } //05 00  KAVPFW.EXE
		$a_00_9 = {53 65 6e 64 4d 61 69 6c } //05 00  SendMail
		$a_00_10 = {4d 69 72 52 65 63 6f 72 64 } //05 00  MirRecord
		$a_00_11 = {41 55 54 48 20 4c 4f 47 49 4e } //01 00  AUTH LOGIN
		$a_00_12 = {4d 41 49 4c 20 46 52 4f 4d 3a } //01 00  MAIL FROM:
		$a_00_13 = {31 32 37 2e 30 2e 30 2e 31 } //02 00  127.0.0.1
		$a_00_14 = {40 79 61 68 6f 6f 2e 63 6f 6d 2e 63 6e } //02 00  @yahoo.com.cn
		$a_00_15 = {53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 53 65 72 76 69 63 65 73 } //02 00  SoftWare\Microsoft\Windows\CurrentVersion\RunServices
		$a_01_16 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //02 00  ReadProcessMemory
		$a_01_17 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //02 00  SetWindowsHookExA
		$a_00_18 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //01 00  CallNextHookEx
		$a_00_19 = {57 53 41 53 74 61 72 74 75 70 } //01 00  WSAStartup
		$a_00_20 = {57 69 6e 45 78 65 63 } //02 00  WinExec
		$a_00_21 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 50 72 6f 63 65 73 73 } //02 00  RegisterServiceProcess
		$a_01_22 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //02 00  CreateToolhelp32Snapshot
		$a_01_23 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  Toolhelp32ReadProcessMemory
	condition:
		any of ($a_*)
 
}