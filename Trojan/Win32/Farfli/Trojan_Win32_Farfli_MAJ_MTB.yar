
rule Trojan_Win32_Farfli_MAJ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 44 24 04 53 56 6a 00 6a 00 6a 02 6a 00 6a 01 68 00 00 00 40 50 32 db ff 15 } //01 00 
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 73 63 76 68 6f 73 74 2e 65 78 65 } //01 00  Program Files\Common Files\scvhost.exe
		$a_01_3 = {63 6d 64 20 2f 43 20 20 72 65 67 65 64 69 74 20 2f 73 20 55 61 63 2e 72 65 67 } //01 00  cmd /C  regedit /s Uac.reg
		$a_01_4 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_01_5 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 } //01 00  Process32First
		$a_01_6 = {47 65 74 4b 65 79 53 74 61 74 65 } //01 00  GetKeyState
		$a_01_7 = {5b 50 61 75 73 65 20 42 72 65 61 6b 5d } //01 00  [Pause Break]
		$a_01_8 = {5b 42 41 43 4b 53 50 41 43 45 5d } //01 00  [BACKSPACE]
		$a_01_9 = {5b 49 4e 53 45 52 54 5d } //00 00  [INSERT]
	condition:
		any of ($a_*)
 
}