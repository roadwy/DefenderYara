
rule Trojan_Win32_Agent_DM{
	meta:
		description = "Trojan:Win32/Agent.DM,SIGNATURE_TYPE_PEHSTR,ffffffe8 00 ffffffe8 00 09 00 00 64 00 "
		
	strings :
		$a_01_0 = {81 fa ff 00 00 00 7f 02 30 10 8b fa 81 e7 01 00 00 80 79 05 4f 83 cf fe 47 85 ff 75 05 } //64 00 
		$a_01_1 = {69 66 20 65 78 69 73 74 20 22 00 00 22 20 67 6f 74 6f 20 4c 6f 6f 70 0d 0a 00 00 00 64 65 6c 20 } //0a 00 
		$a_01_2 = {57 6f 77 2e 65 78 65 } //0a 00  Wow.exe
		$a_01_3 = {57 69 6e 33 32 20 6f 6e 6c 79 21 } //0a 00  Win32 only!
		$a_01_4 = {7b 36 41 30 34 31 46 31 33 2d 41 31 31 31 2d 31 32 41 33 } //01 00  {6A041F13-A111-12A3
		$a_01_5 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //01 00  SeDebugPrivilege
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //01 00  Software\Microsoft\Windows\CurrentVersion\explorer\ShellExecuteHooks
		$a_01_8 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
	condition:
		any of ($a_*)
 
}