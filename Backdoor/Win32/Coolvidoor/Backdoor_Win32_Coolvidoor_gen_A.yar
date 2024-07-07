
rule Backdoor_Win32_Coolvidoor_gen_A{
	meta:
		description = "Backdoor:Win32/Coolvidoor.gen!A,SIGNATURE_TYPE_PEHSTR,17 00 17 00 17 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c } //1 SOFTWARE\Borland\Delphi\
		$a_01_1 = {43 68 61 6e 67 65 53 65 72 76 69 63 65 43 6f 6e 66 69 67 32 41 } //1 ChangeServiceConfig2A
		$a_01_2 = {71 6d 67 72 2e 64 6c 6c } //1 qmgr.dll
		$a_01_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 42 49 54 53 5c 50 61 72 61 6d 65 74 65 72 73 } //1 SYSTEM\CurrentControlSet\Services\BITS\Parameters
		$a_01_4 = {53 68 65 6c 6c 5f 54 72 61 79 57 6e 64 } //1 Shell_TrayWnd
		$a_01_5 = {6c 6f 67 2e 6c 6f 67 } //1 log.log
		$a_01_6 = {57 53 41 53 74 61 72 74 75 70 } //1 WSAStartup
		$a_01_7 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c } //1 \Software\Microsoft\Windows\CurrentVersion\
		$a_01_8 = {57 69 6e 58 70 4d 65 6d 6f 72 79 } //1 WinXpMemory
		$a_01_9 = {43 6f 6f 6c 76 69 62 65 73 } //1 Coolvibes
		$a_01_10 = {57 69 6e 64 6f 77 73 20 58 50 } //1 Windows XP
		$a_01_11 = {4d 53 47 7c 55 6e 69 64 61 64 20 6e 6f 20 61 63 63 65 73 69 62 6c 65 21 } //1 MSG|Unidad no accesible!
		$a_01_12 = {61 76 70 2e 65 78 65 } //1 avp.exe
		$a_01_13 = {6e 6f 64 33 32 6b 72 6e 2e 65 78 65 } //1 nod32krn.exe
		$a_01_14 = {42 69 74 44 65 66 65 6e 64 65 72 } //1 BitDefender
		$a_01_15 = {44 72 2e 57 65 62 } //1 Dr.Web
		$a_01_16 = {4d 63 41 66 65 65 20 50 65 72 73 6f 6e 61 6c 20 46 69 72 65 77 61 6c 6c } //1 McAfee Personal Firewall
		$a_01_17 = {77 69 6e 73 74 61 30 } //1 winsta0
		$a_01_18 = {44 65 73 63 6f 6e 6f 63 69 64 6f } //1 Desconocido
		$a_01_19 = {4f 50 45 4e 55 52 4c } //1 OPENURL
		$a_01_20 = {43 41 50 53 43 52 45 45 4e } //1 CAPSCREEN
		$a_01_21 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 43 4f 4e 46 49 47 } //1 HKEY_CURRENT_CONFIG
		$a_01_22 = {52 45 53 55 4d 45 54 52 41 4e 53 46 45 52 } //1 RESUMETRANSFER
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1) >=23
 
}