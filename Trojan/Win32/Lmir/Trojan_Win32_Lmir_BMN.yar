
rule Trojan_Win32_Lmir_BMN{
	meta:
		description = "Trojan:Win32/Lmir.BMN,SIGNATURE_TYPE_PEHSTR_EXT,55 00 50 00 15 00 00 0a 00 "
		
	strings :
		$a_00_0 = {57 69 6e 53 79 73 4d } //0a 00  WinSysM
		$a_00_1 = {68 74 74 70 3a 2f 2f 65 6b 65 79 2e 73 64 6f 2e 63 6f 6d } //0a 00  http://ekey.sdo.com
		$a_00_2 = {4d 4d 2e 44 4c 4c } //0a 00  MM.DLL
		$a_00_3 = {4d 69 72 2e 65 78 65 } //0a 00  Mir.exe
		$a_00_4 = {57 6f 6f 6f 6c } //0a 00  Woool
		$a_00_5 = {6d 69 72 31 2e 64 61 74 } //0a 00  mir1.dat
		$a_00_6 = {49 47 4d 2e 65 78 65 } //02 00  IGM.exe
		$a_00_7 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //02 00  \drivers\etc\hosts
		$a_00_8 = {5c 48 4f 53 54 53 } //02 00  \HOSTS
		$a_01_9 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //02 00  CreateToolhelp32Snapshot
		$a_01_10 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //02 00  Toolhelp32ReadProcessMemory
		$a_00_11 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //02 00  OpenProcess
		$a_00_12 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //02 00  ShellExecute
		$a_00_13 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //02 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_14 = {61 76 70 63 63 2e } //02 00  avpcc.
		$a_00_15 = {61 76 70 6d 2e } //02 00  avpm.
		$a_00_16 = {61 76 70 33 32 2e } //02 00  avp32.
		$a_00_17 = {61 76 70 2e } //02 00  avp.
		$a_00_18 = {61 6e 74 69 76 69 72 75 73 2e 65 } //02 00  antivirus.e
		$a_00_19 = {66 73 61 76 2e 65 78 65 } //02 00  fsav.exe
		$a_00_20 = {6e 6f 72 74 6f 6e 2e 65 } //00 00  norton.e
	condition:
		any of ($a_*)
 
}