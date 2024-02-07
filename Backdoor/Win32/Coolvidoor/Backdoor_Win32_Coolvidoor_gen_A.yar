
rule Backdoor_Win32_Coolvidoor_gen_A{
	meta:
		description = "Backdoor:Win32/Coolvidoor.gen!A,SIGNATURE_TYPE_PEHSTR,17 00 17 00 17 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c } //01 00  SOFTWARE\Borland\Delphi\
		$a_01_1 = {43 68 61 6e 67 65 53 65 72 76 69 63 65 43 6f 6e 66 69 67 32 41 } //01 00  ChangeServiceConfig2A
		$a_01_2 = {71 6d 67 72 2e 64 6c 6c } //01 00  qmgr.dll
		$a_01_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 42 49 54 53 5c 50 61 72 61 6d 65 74 65 72 73 } //01 00  SYSTEM\CurrentControlSet\Services\BITS\Parameters
		$a_01_4 = {53 68 65 6c 6c 5f 54 72 61 79 57 6e 64 } //01 00  Shell_TrayWnd
		$a_01_5 = {6c 6f 67 2e 6c 6f 67 } //01 00  log.log
		$a_01_6 = {57 53 41 53 74 61 72 74 75 70 } //01 00  WSAStartup
		$a_01_7 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c } //01 00  \Software\Microsoft\Windows\CurrentVersion\
		$a_01_8 = {57 69 6e 58 70 4d 65 6d 6f 72 79 } //01 00  WinXpMemory
		$a_01_9 = {43 6f 6f 6c 76 69 62 65 73 } //01 00  Coolvibes
		$a_01_10 = {57 69 6e 64 6f 77 73 20 58 50 } //01 00  Windows XP
		$a_01_11 = {4d 53 47 7c 55 6e 69 64 61 64 20 6e 6f 20 61 63 63 65 73 69 62 6c 65 21 } //01 00  MSG|Unidad no accesible!
		$a_01_12 = {61 76 70 2e 65 78 65 } //01 00  avp.exe
		$a_01_13 = {6e 6f 64 33 32 6b 72 6e 2e 65 78 65 } //01 00  nod32krn.exe
		$a_01_14 = {42 69 74 44 65 66 65 6e 64 65 72 } //01 00  BitDefender
		$a_01_15 = {44 72 2e 57 65 62 } //01 00  Dr.Web
		$a_01_16 = {4d 63 41 66 65 65 20 50 65 72 73 6f 6e 61 6c 20 46 69 72 65 77 61 6c 6c } //01 00  McAfee Personal Firewall
		$a_01_17 = {77 69 6e 73 74 61 30 } //01 00  winsta0
		$a_01_18 = {44 65 73 63 6f 6e 6f 63 69 64 6f } //01 00  Desconocido
		$a_01_19 = {4f 50 45 4e 55 52 4c } //01 00  OPENURL
		$a_01_20 = {43 41 50 53 43 52 45 45 4e } //01 00  CAPSCREEN
		$a_01_21 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 43 4f 4e 46 49 47 } //01 00  HKEY_CURRENT_CONFIG
		$a_01_22 = {52 45 53 55 4d 45 54 52 41 4e 53 46 45 52 } //00 00  RESUMETRANSFER
	condition:
		any of ($a_*)
 
}